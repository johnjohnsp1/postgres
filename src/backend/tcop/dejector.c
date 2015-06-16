#include "postgres.h"
#include "nodes/nodeFuncs.h"
#include "tcop/dejector.h"
// We can only be built with --with-openssl for now
#include "openssl/sha.h"

// TODO: make this parameterizable to a max of 2^29 (2^(256/8-3))-byte mask
// and up to 8 taps.  Considering that an 8kbit bloom filter with 3 taps is
// likely to be more than large enough, we expect that nobody will ever push
// these parameters to their limits.
#define DEJECTOR_MASK_SIZE 1024
#define DEJECTION_NTAPS 3

// guaranteed to be an array of at least DEJECTOR_MASK_SIZE when queries are
// being processed.
char *dejector_mask = NULL;
bool dejector_enforcing = false;

/*
 * BASE64
 */

static const char _base64[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const int8 b64lookup[128] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
	-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
	-1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
};

static unsigned
b64_encode(const char *src, unsigned len, char *dst)
{
	char	   *p;
	const char *s,
			   *end = src + len;
	int			pos = 2;
	uint32		buf = 0;

	s = src;
	p = dst;

	while (s < end)
	{
		buf |= (unsigned char) *s << (pos << 3);
		pos--;
		s++;

		/* write it out */
		if (pos < 0)
		{
			*p++ = _base64[(buf >> 18) & 0x3f];
			*p++ = _base64[(buf >> 12) & 0x3f];
			*p++ = _base64[(buf >> 6) & 0x3f];
			*p++ = _base64[buf & 0x3f];

			pos = 2;
			buf = 0;
		}
	}
	if (pos != 2)
	{
		*p++ = _base64[(buf >> 18) & 0x3f];
		*p++ = _base64[(buf >> 12) & 0x3f];
		*p++ = (pos == 0) ? _base64[(buf >> 6) & 0x3f] : '=';
		*p++ = '=';
	}

	return p - dst;
}

static unsigned
b64_decode(const char *src, unsigned len, char *dst)
{
	const char *srcend = src + len,
			   *s = src;
	char	   *p = dst;
	char		c;
	int			b = 0;
	uint32		buf = 0;
	int			pos = 0,
				end = 0;

	while (s < srcend)
	{
		c = *s++;

		if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
			continue;

		if (c == '=')
		{
			/* end sequence */
			if (!end)
			{
				if (pos == 2)
					end = 1;
				else if (pos == 3)
					end = 2;
				else
					ereport(ERROR,
							(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
							 errmsg("unexpected \"=\" while decoding base64 sequence")));
			}
			b = 0;
		}
		else
		{
			b = -1;
			if (c > 0 && c < 127)
				b = b64lookup[(unsigned char) c];
			if (b < 0)
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
						 errmsg("invalid symbol '%c' while decoding base64 sequence", (int) c)));
		}
		/* add it to buffer */
		buf = (buf << 6) + b;
		pos++;
		if (pos == 4)
		{
			*p++ = (buf >> 16) & 255;
			if (end == 0 || end > 1)
				*p++ = (buf >> 8) & 255;
			if (end == 0 || end > 2)
				*p++ = buf & 255;
			buf = 0;
			pos = 0;
		}
	}

	if (pos != 0)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("invalid base64 end sequence"),
				 errhint("Input data is missing padding, truncated, or otherwise corrupted.")));

	return p - dst;
}


static unsigned
b64_enc_len(const char *src, unsigned srclen)
{
	/* 3 bytes will be converted to 4 */
	return (srclen + 2) * 4 / 3;
}

static unsigned
b64_dec_len(const char *src, unsigned srclen)
{
	return (srclen * 3) >> 2;
}

/* DEJECTOR */

typedef struct walker_ctx {
	SHA256_CTX sha_ctx;
	bool success;
} walker_ctx;

static bool dejector_filter_statement_walker(Node* node, walker_ctx* ctx);

bool check_dejector_enforcing(bool *newval, void** extra, GucSource source) {
	if (dejector_enforcing && !*newval) {
		// Once dejector is enforcing, it can't be turned off.
		return false;
	}
	return true;
}

bool check_dejector_mask(char** newval, void** extra, GucSource source) {
	// If dejector is enforcing, we don't allow the restrictions to be
	// relaxed.
	char *tmp, *ret = calloc(DEJECTOR_MASK_SIZE, 1);
	unsigned dec_len, in_len = strlen(*newval), iter_count, i;

	if (strlen(*newval) == 0) {
		free(*newval);
		*newval = ret;
		return true;
	}

	tmp = malloc(b64_dec_len(*newval, in_len));
	dec_len = b64_decode(*newval, in_len, tmp);

	if ((dec_len & (dec_len-1)) != 0) {
		/* Non-power-of-two input size */
		// TODO: ereport?
		return false;
	}

	if (dec_len < DEJECTOR_MASK_SIZE) {
		iter_count = DEJECTOR_MASK_SIZE;
	} else {
		iter_count = dec_len;
	}

	for (i = 0; i < iter_count; i++) {
		ret[i % DEJECTOR_MASK_SIZE] |= tmp[i % dec_len];
	}

	if (dejector_enforcing) {
		// Don't allow expanding the filter in enforcing mode
		for (i = 0; i < DEJECTOR_MASK_SIZE; i++) {
			ret[i] &= dejector_mask[i];
		}
	}

	free(*newval);
	free(tmp);
	*newval = tmp;
	return true;
}

const char* show_dejector_mask(void) {
	char* ret = malloc(b64_enc_len((char*)dejector_mask, DEJECTOR_MASK_SIZE) + 1);
	unsigned enc_len = b64_encode((char*)dejector_mask, DEJECTOR_MASK_SIZE, ret);
	ret[enc_len] = 0;
	return ret;
}

void dejector_set_enforcing(bool state) {
	dejector_enforcing = true;
}

bool dejector_get_enforcing(void) {
	return dejector_enforcing;
}

void dejector_clear_mask(void) {
	memset(dejector_mask, 0, DEJECTOR_MASK_SIZE);
}

bool dejector_apply_mask(uint8_t *mask, size_t length) {
	// TODO: It is reasonable to apply a different-sized mask as long as one
	// mask size is a multiple of the other by repeating the smaller one or
	// dividing the larger one into appropriately-sized chunks which are then
	// OR-ed together. This is not implemented in this PoC.

	// TODO: Report error properly
	if (length != DEJECTOR_MASK_SIZE) {
		return false;
	}

	memmove(dejector_mask, mask, DEJECTOR_MASK_SIZE);
	return true;
}


bool dejector_filter_statement(List* stmt_list) {
	walker_ctx ctx;
	unsigned char hash_result[SHA256_DIGEST_LENGTH];
	int i, tap, tap_pos;
	uint8_t tap_mask;
	uint32_t tap_val;
	ListCell *stmt_item;
	SHA256_Init(&ctx.sha_ctx);
	ctx.success = true;

	foreach(stmt_item, stmt_list) {
		Node* stmt = (Node*)lfirst(stmt_item);
		if (dejector_filter_statement_walker(stmt, &ctx))
			break;
	}

	SHA256_Final(hash_result, &ctx.sha_ctx);

	for (tap = 0; tap < DEJECTION_NTAPS; tap++) {
		tap_val = 0;
		for (i = tap * 4; i < tap*4 + 4; i++) {
			tap_val = (tap_val << 8) | hash_result[i];
		}

		// map to bit with mask
		tap_mask = 1 << (tap_val & 0x7);
		tap_pos = (tap_val >> 3) % DEJECTOR_MASK_SIZE;
		if (dejector_enforcing) {
			if (!(dejector_mask[tap_pos] & tap_mask)) {
				return false;
			}
		} else {
			dejector_mask[tap_pos] |= tap_mask;
		}
	}
	return true;
}

static bool dejector_filter_statement_walker(Node* node, walker_ctx* ctx) {
	// Right now, trace messages consist of a operation followed by a 24-bit
	// big-endian node type. This works because Node->type is guaranteed to
	// fit into 24 bits.  If that ever changes, this will need to as well.
	uint8_t trace_msg_buf[4]; // Buffer for trace messages that get hashed
							  // into the context.
	if (node == NULL) {
		return false;
	}

	trace_msg_buf[0] = '{';
	trace_msg_buf[1] = (node->type >> 16) & 0xFF;
	trace_msg_buf[2] = (node->type >>  8) & 0xFF;
	trace_msg_buf[3] = (node->type      ) & 0xFF;
	if (!SHA256_Update(&ctx->sha_ctx, trace_msg_buf, 4)) {
		// TODO: use ereport
		ctx->success = false;
		return true; // cancel walk
	}

	raw_expression_tree_walker(node, dejector_filter_statement_walker, ctx);

	trace_msg_buf[0] = '}';
	trace_msg_buf[1] = (node->type >> 16) & 0xFF;
	trace_msg_buf[2] = (node->type >>  8) & 0xFF;
	trace_msg_buf[3] = (node->type      ) & 0xFF;
	if (!SHA256_Update(&ctx->sha_ctx, trace_msg_buf, 4)) {
		// TODO: use ereport
		ctx->success = false;
		return true; // cancel walk
	}

	return !ctx->success;
}
