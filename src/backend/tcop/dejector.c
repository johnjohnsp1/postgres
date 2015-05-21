#include "postgres.h"
#include "nodes/nodeFuncs.h"
#include "tcop/dejector.h"
// We can only be built with --with-openssl for now
#include "openssl/sha.h"

// TODO: make this parameterizable to a max of 2^29 (2^(256/8-3))-byte mask
// and up to 8 taps.  Considering that an 8kbit bloom filter with 3 taps is
// likely to be more than large enough, we expect that nobody will ever push
// these parameters to their limits.
#define DEJECTION_MASK_SIZE 1024
#define DEJECTION_NTAPS 3
static uint8_t dejection_mask[DEJECTION_MASK_SIZE];
static bool dejector_enforcing = false;

typedef struct walker_ctx {
	SHA256_CTX sha_ctx;
	bool success;
} walker_ctx;

bool dejector_filter_statement_walker(Node* node, walker_ctx* ctx);

void dejector_set_enforcing(bool state) {
	dejector_enforcing = true;
}
bool dejector_get_enforcing(void) {
	return dejector_enforcing;
}

void dejector_clear_mask(void) {
	memset(dejection_mask, 0, DEJECTION_MASK_SIZE);
}

bool dejector_apply_mask(uint8_t *mask, size_t length) {
	// TODO: It is reasonable to apply a different-sized mask as long as one
	// mask size is a multiple of the other by repeating the smaller one or
	// dividing the larger one into appropriately-sized chunks which are then
	// OR-ed together. This is not implemented in this PoC.

	// TODO: Report error properly
	if (length != DEJECTION_MASK_SIZE) {
		return false;
	}

	memmove(dejection_mask, mask, DEJECTION_MASK_SIZE);
	return true;
}


bool dejector_filter_statement(Node* node) {
	walker_ctx ctx;
	unsigned char hash_result[SHA256_DIGEST_LENGTH];
	int i, tap, tap_pos;
	uint8_t tap_mask;
	uint32_t tap_val;
	SHA256_Init(&ctx.sha_ctx);
	ctx.success = true;

	dejector_filter_statement_walker(node, &ctx);

	SHA256_Final(hash_result, &ctx.sha_ctx);

	for (tap = 0; tap < DEJECTION_NTAPS; tap++) {
		for (i = tap * 4; i < tap*4 + 4; i++) {
			tap_val = (tap_val << 8) | hash_result[i];
		}

		// map to bit with mask
		tap_mask = 1 << (tap & 0x7);
		tap_pos = (tap >> 3) % DEJECTION_MASK_SIZE;
		if (dejector_enforcing) {
			if (!(dejection_mask[tap_pos] & tap_mask)) {
				return false;
			}
		} else {
			dejection_mask[tap_pos] |= tap_mask;
		}
	}
	return true;
}

bool dejector_filter_statement_walker(Node* node, walker_ctx* ctx) {
	// Right now, trace messages consist of a operation followed by a 24-bit
	// big-endian node type. This works because Node->type is guaranteed to
	// fit into 24 bits.  If that ever changes, this will need to as well.
	uint8_t trace_msg_buf[4]; // Buffer for trace messages that get hashed
							  // into the context.
	bool ret;
	if (node == NULL) {
		return false;
	}

	trace_msg_buf[0] = '{';
	trace_msg_buf[1] = (node->type >> 16) & 0xFF;
	trace_msg_buf[2] = (node->type >>  8) & 0xFF;
	trace_msg_buf[3] = (node->type      ) & 0xFF;
	if (!SHA256_Update(&ctx->sha_ctx, trace_msg_buf, 4)) {
		ctx->success = false;
		return true; // cancel walk
	}

	ret = raw_expression_tree_walker(node, dejector_filter_statement_walker, ctx);

	trace_msg_buf[0] = '}';
	trace_msg_buf[1] = (node->type >> 16) & 0xFF;
	trace_msg_buf[2] = (node->type >>  8) & 0xFF;
	trace_msg_buf[3] = (node->type      ) & 0xFF;
	if (!SHA256_Update(&ctx->sha_ctx, trace_msg_buf, 4)) {
		ctx->success = false;
		return true; // cancel walk
	}

	return ret;
}
