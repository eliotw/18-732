#include "ast.h"
#include "tables.h"
#include "eval.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

int eval_debug = 0;

void debug_eval(int val)
{
  eval_debug = val;
}

value_t eval_exp(ast_t *e, varctx_t *tbl, memctx_t *mem)
{
  value_t ret;
  switch(e->tag){
    case int_ast: return e->info.integer; break;
    case var_ast: return lookup_var(e->info.varname, tbl); break;
    case node_ast: {
      switch(e->info.node.tag){
        case MEM:
          return load(eval_exp(e->info.node.arguments->elem, tbl,mem), mem);
          break;
        case PLUS:
          return
            eval_exp(e->info.node.arguments->elem,tbl,mem) + 
            eval_exp(e->info.node.arguments->next->elem,tbl,mem);
          break;
        case MINUS:
          return
            eval_exp(e->info.node.arguments->elem,tbl,mem) -
            eval_exp(e->info.node.arguments->next->elem,tbl,mem);
          break;
        case DIVIDE:
          return 
            eval_exp(e->info.node.arguments->elem,tbl,mem) /
            eval_exp(e->info.node.arguments->next->elem,tbl,mem);
          break;
        case TIMES:
          return 
            eval_exp(e->info.node.arguments->elem,tbl,mem) *
            eval_exp(e->info.node.arguments->next->elem,tbl,mem);
          break;
        case EQ:
          if(eval_debug) printf("[Debug] EQ: %u == %u\n", eval_exp(e->info.node.arguments->elem,tbl,mem), eval_exp(e->info.node.arguments->next->elem,tbl,mem));
          return 
            (eval_exp(e->info.node.arguments->elem,tbl,mem) ==
             eval_exp(e->info.node.arguments->next->elem,tbl,mem));
          break;
        case NEQ:
          return 
            (eval_exp(e->info.node.arguments->elem,tbl,mem) != 
             eval_exp(e->info.node.arguments->next->elem,tbl,mem));
          break;
        case GT:
          return (eval_exp(e->info.node.arguments->elem,tbl,mem) > 
            eval_exp(e->info.node.arguments->next->elem,tbl,mem));
            break;
        case LT:
          return (eval_exp(e->info.node.arguments->elem,tbl,mem) <
            eval_exp(e->info.node.arguments->next->elem,tbl,mem));
            break;
        case LEQ:
          return (eval_exp(e->info.node.arguments->elem,tbl,mem) <= 
            eval_exp(e->info.node.arguments->next->elem,tbl,mem));
            break;
        case GEQ:
          return (eval_exp(e->info.node.arguments->elem,tbl,mem) >=
            eval_exp(e->info.node.arguments->next->elem,tbl,mem));
            break;
        case AND:
          return (eval_exp(e->info.node.arguments->elem,tbl,mem) && 
            eval_exp(e->info.node.arguments->next->elem,tbl,mem));
            break;
        case OR:
          return (eval_exp(e->info.node.arguments->elem,tbl,mem) ||
            eval_exp(e->info.node.arguments->next->elem,tbl,mem));
          break;
        case NEGATIVE:
          return -(eval_exp(e->info.node.arguments->elem,tbl,mem));
        case NOT:
          return !(eval_exp(e->info.node.arguments->elem,tbl,mem));
        case IFE:
          return  eval_exp(e->info.node.arguments->elem,tbl,mem)?
                  eval_exp(e->info.node.arguments->next->elem,tbl,mem):
                  eval_exp(e->info.node.arguments->next->next->elem,tbl,mem);
        case READINT:
          printf("> ");
          scanf("%d", &ret);
          return ret;
          break;
        case READSECRETINT:
          printf("# ");
          scanf("%d", &ret);
          return ret;
          break;
        default:
          assert(0); // Unknown/unhandled op.
      }
    }
  }
}

taint_list_t *taint_exp(ast_t *e, varctx_t *tbl, memctx_t *mem)
{
  taint_list_t *ret1, *ret2, *i;
  switch(e->tag){
    case int_ast:
      ret1 = (taint_list_t *)malloc(sizeof(taint_list_t));
      ret1->name = "None";
      ret1->next = NULL;
      return ret1;
      break;
    case var_ast:
      if (eval_debug)
        printf("[Debug] heading into taint_var\n");
      return taint_var(e->info.varname, tbl);
      if (eval_debug)
        printf("[Debug] made it past taint_var\n");
      break;
    case node_ast: {
      switch(e->info.node.tag){
        case MEM:
          if (eval_debug) {
            printf("[Debug] taint_exp: addr %d\n", eval_exp(e->info.node.arguments->elem, tbl, mem));
          }
          return taint_addr(eval_exp(e->info.node.arguments->elem, tbl,mem), mem);
          break;
        case PLUS:
          ret1 = taint_exp(e->info.node.arguments->elem,tbl,mem);
          ret2 = taint_exp(e->info.node.arguments->next->elem,tbl,mem);
          if (!is_tainted(ret1)) {
            return ret2;
          } else if (!is_tainted(ret2)) {
            return ret1;
          } else {
            i = ret1;
            while (i->next != NULL)
              i = i->next;
            i->next = ret2;
            return ret1;
          }
          break;
        case MINUS:
          ret1 = taint_exp(e->info.node.arguments->elem,tbl,mem);
          ret2 = taint_exp(e->info.node.arguments->next->elem,tbl,mem);
          if (!is_tainted(ret1)) {
            return ret2;
          } else if (!is_tainted(ret2)) {
            return ret1;
          } else {
            i = ret1;
            while (i->next != NULL)
              i = i->next;
            i->next = ret2;
            return ret1;
          }
          break;
        case DIVIDE:
          ret1 = taint_exp(e->info.node.arguments->elem,tbl,mem);
          ret2 = taint_exp(e->info.node.arguments->next->elem,tbl,mem);
          if (!is_tainted(ret1)) {
            return ret2;
          } else if (!is_tainted(ret2)) {
            return ret1;
          } else {
            i = ret1;
            while (i->next != NULL)
              i = i->next;
            i->next = ret2;
            return ret1;
          }
          break;
        case TIMES:
          if(eval_debug) {
            printf("[Debug] TIMES: %u * \n", e->info.node.arguments->next->elem->info.integer);
          }
          /*if(e->info.node.arguments->next->elem->info.integer == 0 || e->info.node.arguments->elem->info.integer) {
              ret1 = (taint_list_t *)malloc(sizeof(taint_list_t));
              ret1->name = "None";
              ret1->next = NULL;
              return ret1;
          }*/
          ret1 = taint_exp(e->info.node.arguments->elem,tbl,mem);
          ret2 = taint_exp(e->info.node.arguments->next->elem,tbl,mem);
          if (!is_tainted(ret1)) {
            return ret2;
          } else if (!is_tainted(ret2)) {
            return ret1;
          } else {
            i = ret1;
            while (i->next != NULL)
              i = i->next;
            i->next = ret2;
            return ret1;
          }
          break;
        case EQ:
          ret1 = taint_exp(e->info.node.arguments->elem,tbl,mem);
          ret2 = taint_exp(e->info.node.arguments->next->elem,tbl,mem);
          if (!is_tainted(ret1)) {
            return ret2;
          } else if (!is_tainted(ret2)) {
            return ret1;
          } else {
            i = ret1;
            while (i->next != NULL)
              i = i->next;
            i->next = ret2;
            return ret1;
          }
          break;
        case NEQ:
          ret1 = taint_exp(e->info.node.arguments->elem,tbl,mem);
          ret2 = taint_exp(e->info.node.arguments->next->elem,tbl,mem);
          if (!is_tainted(ret1)) {
            return ret2;
          } else if (!is_tainted(ret2)) {
            return ret1;
          } else {
            i = ret1;
            while (i->next != NULL)
              i = i->next;
            i->next = ret2;
            return ret1;
          }
          break;
        case GT:
          ret1 = taint_exp(e->info.node.arguments->elem,tbl,mem);
          ret2 = taint_exp(e->info.node.arguments->next->elem,tbl,mem);
          if (!is_tainted(ret1)) {
            return ret2;
          } else if (!is_tainted(ret2)) {
            return ret1;
          } else {
            i = ret1;
            while (i->next != NULL)
              i = i->next;
            i->next = ret2;
            return ret1;
          }
          break;
        case LT:
          ret1 = taint_exp(e->info.node.arguments->elem,tbl,mem);
          ret2 = taint_exp(e->info.node.arguments->next->elem,tbl,mem);
          if (!is_tainted(ret1)) {
            return ret2;
          } else if (!is_tainted(ret2)) {
            return ret1;
          } else {
            i = ret1;
            while (i->next != NULL)
              i = i->next;
            i->next = ret2;
            return ret1;
          }
          break;
        case LEQ:
          ret1 = taint_exp(e->info.node.arguments->elem,tbl,mem);
          ret2 = taint_exp(e->info.node.arguments->next->elem,tbl,mem);
          if (!is_tainted(ret1)) {
            return ret2;
          } else if (!is_tainted(ret2)) {
            return ret1;
          } else {
            i = ret1;
            while (i->next != NULL)
              i = i->next;
            i->next = ret2;
            return ret1;
          }
          break;
        case GEQ:
          ret1 = taint_exp(e->info.node.arguments->elem,tbl,mem);
          ret2 = taint_exp(e->info.node.arguments->next->elem,tbl,mem);
          if (!is_tainted(ret1)) {
            return ret2;
          } else if (!is_tainted(ret2)) {
            return ret1;
          } else {
            i = ret1;
            while (i->next != NULL)
              i = i->next;
            i->next = ret2;
            return ret1;
          }
          break;
        case AND:
          ret1 = taint_exp(e->info.node.arguments->elem,tbl,mem);
          ret2 = taint_exp(e->info.node.arguments->next->elem,tbl,mem);
          if (!is_tainted(ret1)) {
            return ret2;
          } else if (!is_tainted(ret2)) {
            return ret1;
          } else {
            i = ret1;
            while (i->next != NULL)
              i = i->next;
            i->next = ret2;
            return ret1;
          }
          break;
        case OR:
          ret1 = taint_exp(e->info.node.arguments->elem,tbl,mem);
          ret2 = taint_exp(e->info.node.arguments->next->elem,tbl,mem);
          if (!is_tainted(ret1)) {
            return ret2;
          } else if (!is_tainted(ret2)) {
            return ret1;
          } else {
            i = ret1;
            while (i->next != NULL)
              i = i->next;
            i->next = ret2;
            return ret1;
          }
          break;
        case NEGATIVE:
          return taint_exp(e->info.node.arguments->elem,tbl,mem);
        case NOT:
          return taint_exp(e->info.node.arguments->elem,tbl,mem);
        case IFE:
          return eval_exp(e->info.node.arguments->elem,tbl,mem) ? taint_exp(e->info.node.arguments->next->elem,tbl,mem): taint_exp(e->info.node.arguments->next->next->elem,tbl,mem);
          break;
        case READINT:
          if (eval_debug)
            printf("[Debug] reading regular int\n");
          ret1 = (taint_list_t *)malloc(sizeof(taint_list_t));
          ret1->name = "None";
          ret1->next = NULL;
          return ret1;
          break;
        case READSECRETINT:
          if (eval_debug)
            printf("[Debug] reading secret int\n");
          ret1 = (taint_list_t *)malloc(sizeof(taint_list_t));
          ret1->name = "Direct";
          ret1->next = NULL;
          return ret1;
          break;
        default:
          assert(0); // Unknown/unhandled op.
      }
    }
  }
}

state_t* eval_stmts(ast_t *p, state_t *state)
{
  ast_list_t *stmts;
  ast_list_t *ip;
  ast_t *t1, *t2;
  ast_t *s;
  value_t v;
  taint_list_t *list;
  int taint;
  value_t addr;

  assert(p != NULL);
  assert(p->info.node.tag == SEQ);
  ip = p->info.node.arguments;

  while(ip != NULL)
  {
    s = ip->elem;
    if (eval_debug)
      printf("[Debug] statement: %d\n", s->info.node.tag);
    switch(s->info.node.tag){
      case ASSIGN:
        /* the lhs */
        t1 = s->info.node.arguments->elem;
        /* the rhs */
        t2 = s->info.node.arguments->next->elem;
        v = eval_exp(t2, state->tbl, state->mem);
        list = taint_exp(t2, state->tbl, state->mem);
        taint = is_tainted(list);
        switch(t1->tag){
          /* update with taint information */
          case var_ast:
            state->tbl = update_var(t1->info.string, v, taint, state->tbl);
            break;
          case node_ast:
            assert(t1->info.node.tag == MEM);
            addr = eval_exp(t1->info.node.arguments->elem,
                            state->tbl,
                            state->mem);
            state->mem = store(addr, v, taint, state->mem);
            break;
          default:
            assert(0);
        }
        break;
      case PRINT:
        if (eval_debug)
          printf("[Debug] print statement\n");
        switch(s->info.node.arguments->elem->tag){
          case str_ast:
            printf("%s\n", s->info.node.arguments->elem->info.string);
            fprintf(stderr, "Tainted variable: None\n");
            break;
          default:
            list = taint_exp(s->info.node.arguments->elem, state->tbl, state->mem);
            if (is_tainted(list)) {
              if (eval_debug)
                printf("[Debug] suppressing tainted print\n");
              printf("<secret>\n");
            } else {
              if (eval_debug)
                printf("[Debug] safe print\n");
            printf("%d\n", eval_exp(s->info.node.arguments->elem, 
                                    state->tbl,
                                    state->mem));
            }
            if (eval_debug)
              printf("[Debug] calling taint analysis\n");
            taint_analysis(list);
            break;
        }
        break;
      case IF:
        if(eval_exp(s->info.node.arguments->elem, state->tbl, state->mem)){
          state = eval_stmts(s->info.node.arguments->next->elem, state);
        } else {
          state = eval_stmts(s->info.node.arguments->next->next->elem, state);
        }
        break;
      case SEQ:
        state = eval_stmts(s->info.node.arguments->next->elem, state);
        break;
      case ASSERT:
        if(eval_exp(s->info.node.arguments->elem, state->tbl,state->mem) ==0){
          printf("Assert failed!\n");
        }
        break;
      default:
        printf("Unknown statement type\n");
        assert(0);
        break;
    }
    ip = ip->next;
  }
  return state;
}

int is_tainted(taint_list_t *list)
{
  char none[] = "None";
  if (eval_debug) {
    printf("[Debug] is_tainted: %s and %s\n", list->name, none);
  }
  return (strcmp(list->name, none));
}

void taint_analysis(taint_list_t *list)
{
  fprintf(stderr, "Tainted variable: ");
  while (list) {
    if (eval_debug)
      printf("[Debug] taint_analysis: %s\n", list->name);
    fprintf(stderr, "%s", list->name);
    if (list->next) {
      fprintf(stderr, ", ");
    }
    list = list->next;
  }
  fprintf(stderr, "\n");
}

