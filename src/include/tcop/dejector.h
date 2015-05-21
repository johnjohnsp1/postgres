#ifndef DEJECTOR_H
#define DEJECTOR_H

/**
 * This function either adds the current statement into the current dejection
 * mask or determines if the statement is allowed by the current dejection
 * mask, depending on whether the dejection mask is in learning or enforcing
 * mode, respectively.
 */
bool dejector_filter_statement(Node* node);

void dejector_clear_mask(void);

bool dejector_apply_mask(uint8_t* mask, size_t length);

void dejector_get_mask(uint8_t** mask, size_t *length);

void dejector_set_enforcing(bool state);
bool dejector_get_enforcing(void);
#endif
