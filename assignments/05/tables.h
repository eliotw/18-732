#ifndef taint_hw_tables_h
#define taint_hw_tables_h

#include <stdio.h>

typedef int value_t;

typedef int bool;

#define true 1
#define false 0

#define DEFAULT_VAL 0

typedef struct mod_val {
   value_t val;
   bool tainted;
   struct taint_list_t *list;
} mod_val;

typedef struct varctx_t {
  char *name;
  value_t val;
  bool tainted;
  struct varctx_t *next;
} varctx_t;

typedef struct memctx_t {
  unsigned int addr;
  value_t val;
  bool tainted;
  struct memctx_t *next;
} memctx_t; 

typedef struct taint_list_t {
      char *name;
        struct taint_list_t *next;
} taint_list_t;

/* Extends the context o to include a new variable. The initial value
   is DEFAULT_VAL */
varctx_t *newvar(char *name, varctx_t *o);

/* returns the value corresponding to a variable in a context. Returns
   DEFAULT_VAL if no such name exists */
mod_val lookup_var(char *name, varctx_t *c);

taint_list_t *taint_var(char *name, varctx_t *c);

/* update a variable. returns a new context, which may be different
   than c */
varctx_t *update_var(char *name, mod_val val, varctx_t *c);

/* updates our context c to bind value to address. Returns a new
   context with the updated binding (which may be different than c) */
memctx_t *store(unsigned int addr, mod_val val, memctx_t *c);

/* load a value. Returns DEFAULT_VAL if there is no value for addr */
mod_val load(unsigned int addr, memctx_t *c);

/* prints out the memory context */
void print_memctx(memctx_t *);

#endif
