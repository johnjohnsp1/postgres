#ifndef DEJECTOR_H
#define DEJECTOR_H
#include "nodes/nodes.h"
#include "utils/guc.h"
/**
 * This function either adds the current statement into the current dejection
 * mask or determines if the statement is allowed by the current dejection
 * mask, depending on whether the dejection mask is in learning or enforcing
 * mode, respectively.
 */
bool dejector_filter_statement(List* node);

void dejector_clear_mask(void);

bool dejector_apply_mask(uint8_t* mask, size_t length);

void dejector_get_mask(uint8_t** mask, size_t *length);

void dejector_set_enforcing(bool state);
bool dejector_get_enforcing(void);

const char* show_dejector_mask(void);
bool check_dejector_mask(char** newval, void** extra, GucSource source);
bool check_dejector_enforcing(bool *newval, void** extra, GucSource source);

extern char *dejector_mask;
extern bool dejector_enforcing;

#endif
