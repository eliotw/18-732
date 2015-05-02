#ifndef EVAL_H
#define EVAL_H
#include "tables.h"

typedef struct state_t {
    varctx_t *tbl;
    memctx_t *mem;
} state_t;

void debug_eval(int);
value_t eval_exp(ast_t *e, varctx_t *tbl, memctx_t *mem);
taint_list_t *taint_exp(ast_t *e, varctx_t *tbl, memctx_t *mem);
state_t * eval_stmts(ast_t *program, state_t *state);
int is_tainted(taint_list_t *list);
void taint_analysis(taint_list_t *list);

#endif
