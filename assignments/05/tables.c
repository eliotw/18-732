#include <stdlib.h>
#include "tables.h"

extern int eval_debug;


varctx_t *newvar(char *name, varctx_t *o)
{
  varctx_t *n = (varctx_t *)malloc(sizeof(varctx_t));
  n->name = name;
  n->val = DEFAULT_VAL;
  n->next = o;
  return n;
}

mod_val lookup_var(char *name, varctx_t *c)
{
    mod_val ret;
  while(c != NULL){
    if(strcmp(c->name, name) == 0){
      if(eval_debug)
        printf("[Debug] lookup: %s value: %x taint: %x\n", name, c->val, c->tainted);

      ret.val = c->val;
      ret.tainted = c->tainted;

      return ret;
    }
    c=c->next;
  }
  if(eval_debug)
    printf("[Debug] lookup: %s <uninitialized. returning %d>", name, DEFAULT_VAL);

  ret.val = DEFAULT_VAL;
  ret.tainted = false;
  return ret;
}

taint_list_t *taint_var(char *name, varctx_t *c)
{
  taint_list_t *ret = (taint_list_t *)malloc(sizeof(taint_list_t));
  ret->name = "None";
  ret->next = NULL;
  while(c != NULL){
    if(strcmp(c->name, name) == 0){
      if(eval_debug)
        printf("[Debug] taint_var: %s value: %d\n", name, c->tainted);
      if (c->tainted)
        ret->name = name;
      return ret;
    }
    c=c->next;
  }
  if(eval_debug)
    printf("[Debug] taint_var: %s <uninitialized. returning empty taint list>", name);
  return ret;
}

varctx_t * update_var(char *name, mod_val val, varctx_t *o)
{
  varctx_t *c = o;
  varctx_t *n = NULL;

  while(c != NULL){
    if(strcmp(c->name, name) == 0){
      if(eval_debug){
	printf("[Debug] update %s with %x (old value %x), taint status: %x (old value %x)\n", name, val.val, c->val, val.tainted, c->tainted);
      }
      c->val = val.val;
      c->tainted = val.tainted;
      return o;
    }
    c= c->next;
  }
  n = (varctx_t *)malloc(sizeof(varctx_t));
  n->name = name;
  n->val = val.val;
  n->tainted = val.tainted;
  n->next = o;
  if(eval_debug){
    printf("[Debug] update %s with %x (new node), taint status: %x\n", name, val.val, n->tainted);
  }

  return n;
}

memctx_t *store(unsigned int addr, mod_val val, memctx_t *o)
{
  memctx_t *n = NULL;
  memctx_t *c = o;
  while(c != NULL){
    if(c->addr == addr){
      if(eval_debug){
	printf("[Debug] store %x with %x (replacing %x), taint status: %x (replacing %x)\n", c->addr,
	       val.val, c->val, val.tainted, c->tainted);
      }

      c->val = val.val;
      c->tainted = val.tainted;
      return o;
    }
    c = c->next;
  }
  /* we didn't find the address. create a new spot in the context */
  n = (memctx_t *)(malloc(sizeof(memctx_t)));
  n->addr = addr;
  n->val = val.val;
  n->tainted = val.tainted;
  n->next = o;
  if(eval_debug){
    printf("[Debug] store %x with %x (new node), taint status: %x\n", n->addr, val.val, val.tainted);
  }

  return n;
}

mod_val load(unsigned int addr, memctx_t *c)
{
    mod_val ret;
  while(c != NULL){
    if(c->addr == addr){
      if(eval_debug)
        printf("[Debug] load: %x value: %x, taint status: %x\n", addr, c->val, c->tainted);

      ret.val = c->val;
      ret.tainted = c->tainted;

      return ret;
    }
    c = c->next;
  }
  printf("[Debug] load: %x <uninitialized. returning %x>\n", addr, DEFAULT_VAL);

  ret.val = DEFAULT_VAL;
  ret.tainted = false;
  return ret;
}


void print_memctx(memctx_t *c)
{
  while(c != NULL){
    printf("[Debug] mem[%x] =  %x\n", c->addr, c->val);
    c = c->next;
  }
}
