#include <stdlib.h>
#include <string.h>
#include "tables.h"

extern int eval_debug;


varctx_t *newvar(char *name, varctx_t *o)
{
  varctx_t *n = (varctx_t *)malloc(sizeof(varctx_t));
  n->name = name;
  n->val = DEFAULT_VAL;
  n->taint = 0;
  n->next = o;
  return n;
}

value_t lookup_var(char *name, varctx_t *c)
{
  while(c != NULL){
    if(strcmp(c->name, name) == 0){
      if(eval_debug)
        printf("[Debug] lookup: %s value: %x\n", name, c->val);
      return c->val;
    }
    c=c->next;
  }
  if(eval_debug)
    printf("[Debug] lookup: %s <uninitialized. returning %d>\n", name, DEFAULT_VAL);
  return DEFAULT_VAL;
}

taint_list_t *taint_var(char *name, varctx_t *c)
{
  taint_list_t *ret = (taint_list_t *)malloc(sizeof(taint_list_t));
  ret->name = "None";
  ret->next = NULL;
  while(c != NULL){
    if(strcmp(c->name, name) == 0){
      if(eval_debug)
        printf("[Debug] taint_var: %s value: %d\n", name, c->taint);
      if (c->taint)
        ret->name = name;
      return ret;
    }
    c=c->next;
  }
  if(eval_debug)
    printf("[Debug] taint_var: %s <uninitialized. returning empty taint list>", name);
  return ret;
}

varctx_t * update_var(char *name, value_t val, int taint, varctx_t *o)
{
  varctx_t *c = o;
  varctx_t *n = NULL;

  while(c != NULL){
    if(strcmp(c->name, name) == 0){
      if(eval_debug){
        printf("[Debug] update %s with %x (old value %x), taint: \n", name, val, c->val, taint);
      }
      c->val = val;
      c->taint = taint;
      return o;
    }
    c= c->next;
  }
  n = (varctx_t *)malloc(sizeof(varctx_t));
  n->name = name;
  n->val = val;
  n->taint = taint;
  n->next = o;
  if(eval_debug){
    printf("[Debug] update var %s with %d (new node), taint: %u\n", name, val, taint);
  }

  return n;
}

memctx_t *store(unsigned int addr, value_t val, int taint, memctx_t *o)
{
  memctx_t *n = NULL;
  memctx_t *c = o;
  while(c != NULL){
    if(c->addr == addr){
      if(eval_debug){
        printf("[Debug] store addr %x with %d (replacing %d)\n", c->addr,
         val, c->val);
      }
      c->val = val;
      c->taint = taint;
      if (taint && eval_debug)
        printf("[Debug] tainting addr %x\n", c->addr);
      return o;
    }
    c = c->next;
  }
  /* we didn't find the address. create a new spot in the context */
  n = (memctx_t *)(malloc(sizeof(memctx_t)));
  n->addr = addr;
  n->val = val;
  n->taint = taint;
  if (taint && eval_debug)
    printf("[Debug] tainting new addr %x\n", n->addr);
  n->next = o;
  if(eval_debug){
    printf("[Debug] store address %x with %d (new node)\n", n->addr, val);
  }

  return n;
}

value_t load(unsigned int addr, memctx_t *c)
{
  while(c != NULL){
    if(c->addr == addr){
      if(eval_debug)
        printf("[Debug] load: %x value: %x\n", addr, c->val);
      return c->val;
    }
    c = c->next;
  }
  if (eval_debug)
    printf("[Debug] load: %x <uninitialized. returning %x>\n", addr, DEFAULT_VAL);
  return DEFAULT_VAL;
}

taint_list_t *taint_addr(unsigned int addr, memctx_t *c)
{
  taint_list_t *ret = (taint_list_t *)malloc(sizeof(taint_list_t));
  ret->name = "None";
  ret->next = NULL;
  while(c != NULL){
    if(c->addr == addr){
      if(eval_debug)
        printf("[Debug] taint_addr: %x value: %d\n", addr, c->taint);
      if (c->taint) {
        ret->name = malloc(MAX_ADDR*sizeof(char));
        sprintf(ret->name, "mem[%d]", addr);
      }
      return ret;
    }
    c = c->next;
  }
  if (eval_debug)
    printf("[Debug] taint_addr: %x <uninitialized. returning empty taint list>\n", addr);
  return ret;
}

void print_memctx(memctx_t *c)
{
  while(c != NULL){
    printf("[Debug] mem[%x] =  %x\n", c->addr, c->val);
    c = c->next;
  }
}
