#include "ast.h"
#include "tables.h"
#include "eval.h"
#include <assert.h>
#include <stdlib.h>

int eval_debug = 0;

void debug_eval(int val)
{
    eval_debug = val;
}

bool combine_taint(bool t1, bool t2) {
    if(t1 == true || t2 == true) return true;
    return false;    
}

taint_list_t *combine_taint_list(taint_list_t *t1, taint_list_t *t2) {
    taint_list_t *n = t1;
    if(n == NULL) return t2;
    else if(t2 == NULL) return t1;
    else {
        while(n->next != NULL) {
            n = n->next;
        }
        n->next = t2;
    }

    return t1;
}

void add_taint_to_list(char *name, taint_list_t *print) {
    if(eval_debug) printf("[Debug] adding %s to taint list\n", name);
    taint_list_t *n = print;
    if(print->name == NULL) {
        if(eval_debug) printf("[Debug] list is empty, creating new list"); 
        print->name = name;
    } else {
        while(n->next != NULL) {
            printf("Found %u", n->name);
            if(n->name == name) return;
            n = n->next;
        }
        taint_list_t *new = (taint_list_t *)malloc(sizeof(taint_list_t));    
        new->name = name;
        new->next = NULL;
        n->next = new;
    }
}

mod_val eval_exp(ast_t *e, varctx_t *tbl, memctx_t *mem, taint_list_t *print)
{
  value_t ret;
  mod_val mod_ret;
  mod_val mod_ret1;
  mod_val mod_ret2;
  mod_val mod_temp;
  char *memret = malloc(12);
    switch(e->tag){
    case int_ast: 
        mod_ret.val = e->info.integer;
        mod_ret.tainted = false;
        return mod_ret;
        break;
    case var_ast: 
        if(eval_debug) printf("[Debug] var_ast");
        mod_ret = lookup_var(e->info.varname, tbl);

        if(mod_ret.tainted == true) {
            add_taint_to_list(e->info.varname, print);
        }

        return mod_ret;
        break;
    case node_ast: {
	switch(e->info.node.tag){
	case MEM:
        mod_ret = load(eval_exp(e->info.node.arguments->elem, tbl,mem, print).val, mem);
        
        if(mod_ret.tainted == true) {
            sprintf(memret, "mem[%u]", mem->addr);
            add_taint_to_list(memret, print);
        }
        return mod_ret;
	  break;
	case PLUS:
      mod_ret1 = eval_exp(e->info.node.arguments->elem,tbl,mem, print);
      mod_ret2 = eval_exp(e->info.node.arguments->next->elem,tbl,mem, print);
      mod_ret.val = mod_ret1.val + mod_ret2.val;
      mod_ret.tainted = combine_taint(mod_ret1.tainted, mod_ret2.tainted);
      return mod_ret;
	  break;
	case MINUS:
	    mod_ret1 = eval_exp(e->info.node.arguments->elem,tbl,mem, print);
        mod_ret2 = eval_exp(e->info.node.arguments->next->elem,tbl,mem, print);
        mod_ret.val = mod_ret1.val - mod_ret2.val;
        mod_ret.tainted = combine_taint(mod_ret1.tainted, mod_ret2.tainted);
        return mod_ret;
	  break;
	case DIVIDE:
	    mod_ret1 = eval_exp(e->info.node.arguments->elem,tbl,mem, print);
	    mod_ret2 = eval_exp(e->info.node.arguments->next->elem,tbl,mem, print);
        mod_ret.val = mod_ret1.val / mod_ret2.val;
        mod_ret.tainted = combine_taint(mod_ret1.tainted, mod_ret2.tainted);
        return mod_ret;
	  break;
	case TIMES:
	    mod_ret1 = eval_exp(e->info.node.arguments->elem,tbl,mem, print);
	    mod_ret2 = eval_exp(e->info.node.arguments->next->elem,tbl,mem, print);
        mod_ret.val = mod_ret1.val * mod_ret2.val;
        mod_ret.tainted = combine_taint(mod_ret1.tainted, mod_ret2.tainted);
        if(eval_debug)
            printf("[Debug] times: %u * %u, taint: %u\n", e->info.node.arguments->elem->info.string, e->info.node.arguments->next->elem->info.string, mod_ret.tainted);
        return mod_ret;
	  break;

	case EQ:
          mod_ret1 = eval_exp(e->info.node.arguments->elem,tbl,mem, print);
	      mod_ret2 = eval_exp(e->info.node.arguments->next->elem,tbl,mem, print);
          mod_ret.val = (mod_ret1.val == mod_ret2.val);
          mod_ret.tainted = combine_taint(mod_ret1.tainted, mod_ret2.tainted);
          if(eval_debug) {
              printf("[Debug] EQ: %u == %u", mod_ret1.val, mod_ret2.val);
          }
          return mod_ret;
	  break;
	case NEQ:
          mod_ret1 = eval_exp(e->info.node.arguments->elem,tbl,mem, print);
	      mod_ret2 = eval_exp(e->info.node.arguments->next->elem,tbl,mem, print);
          mod_ret.val = (mod_ret1.val != mod_ret2.val);
          mod_ret.tainted = combine_taint(mod_ret1.tainted, mod_ret2.tainted);
          return mod_ret;
	  break;
	case GT:
          mod_ret1 = eval_exp(e->info.node.arguments->elem,tbl,mem, print);
	      mod_ret2 = eval_exp(e->info.node.arguments->next->elem,tbl,mem, print);
          mod_ret.val = (mod_ret1.val > mod_ret2.val);
          mod_ret.tainted = combine_taint(mod_ret1.tainted, mod_ret2.tainted);
          return mod_ret;
	    break;
	case LT:
          mod_ret1 = eval_exp(e->info.node.arguments->elem,tbl,mem, print);
	      mod_ret2 = eval_exp(e->info.node.arguments->next->elem,tbl,mem, print);
          mod_ret.val = (mod_ret1.val < mod_ret2.val);
          mod_ret.tainted = combine_taint(mod_ret1.tainted, mod_ret2.tainted);
          return mod_ret;
	    break;
	case LEQ:
          mod_ret1 = eval_exp(e->info.node.arguments->elem,tbl,mem, print);
	      mod_ret2 = eval_exp(e->info.node.arguments->next->elem,tbl,mem, print);
          mod_ret.val = (mod_ret1.val <= mod_ret2.val);
          mod_ret.tainted = combine_taint(mod_ret1.tainted, mod_ret2.tainted);
          return mod_ret;
	    break;
	case GEQ:
          mod_ret1 = eval_exp(e->info.node.arguments->elem,tbl,mem, print);
	      mod_ret2 = eval_exp(e->info.node.arguments->next->elem,tbl,mem, print);
          mod_ret.val = (mod_ret1.val >= mod_ret2.val);
          mod_ret.tainted = combine_taint(mod_ret1.tainted, mod_ret2.tainted);
          return mod_ret;
	    break;
	case AND:
          mod_ret1 = eval_exp(e->info.node.arguments->elem,tbl,mem, print);
	      mod_ret2 = eval_exp(e->info.node.arguments->next->elem,tbl,mem, print);
          mod_ret.val = (mod_ret1.val && mod_ret2.val);
          mod_ret.tainted = combine_taint(mod_ret1.tainted, mod_ret2.tainted);
          return mod_ret;
	    break;
	case OR:
          mod_ret1 = eval_exp(e->info.node.arguments->elem,tbl,mem, print);
	      mod_ret2 = eval_exp(e->info.node.arguments->next->elem,tbl,mem, print);
          mod_ret.val = (mod_ret1.val || mod_ret2.val);
          mod_ret.tainted = combine_taint(mod_ret1.tainted, mod_ret2.tainted);
          return mod_ret;
	  break;
	case NEGATIVE:
            mod_ret1 = eval_exp(e->info.node.arguments->elem,tbl,mem, print);
            mod_ret1.val = -(mod_ret1.val);
            return mod_ret1;
	case NOT:
            mod_ret1 = eval_exp(e->info.node.arguments->elem,tbl,mem, print);
            mod_ret1.val = !(mod_ret1.val);
            return mod_ret1;
    case IFE:
            mod_temp = eval_exp(e->info.node.arguments->elem,tbl,mem, print);
            mod_ret1 = eval_exp(e->info.node.arguments->next->elem,tbl,mem, print);
            mod_ret2 = eval_exp(e->info.node.arguments->next->next->elem,tbl,mem, print); 
            mod_ret.val = mod_temp.val ? mod_ret1.val : mod_ret2.val;
            mod_ret.tainted = mod_temp.val ? mod_ret1.tainted : mod_ret2.tainted;
            return mod_ret;
	case READINT:
	  printf("> ");
	  scanf("%d", &ret);
      mod_ret.val = ret;
      mod_ret.tainted = false;
	  return mod_ret;
	  break;
	case READSECRETINT:
	  printf("# ");
	  scanf("%d", &ret);
      mod_ret.val = ret;
      mod_ret.tainted = true;
      add_taint_to_list("Direct", print);
	  return mod_ret;
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
    mod_val mod_v;
    struct taint_list_t print = {NULL, NULL};

    assert(p != NULL);
    assert(p->info.node.tag == SEQ);
    ip = p->info.node.arguments;
    while(ip != NULL)
    {
	s = ip->elem;

	switch(s->info.node.tag){
	case ASSIGN:
	    /* the lhs */
	    t1 = s->info.node.arguments->elem;
	    /* the rhs */
	    t2 = s->info.node.arguments->next->elem;
        mod_v = eval_exp(t2, state->tbl, state->mem, &print);
	    switch(t1->tag){
	    case var_ast:
		state->tbl = update_var(t1->info.string, mod_v, state->tbl);
		break;
	    case node_ast:
		assert(t1->info.node.tag == MEM);
		state->mem = store(eval_exp(t1->info.node.arguments->elem,
					  state->tbl, 
					  state->mem, &print).val, mod_v, state->mem);
		break;
	    default:
		assert(0);
	    }
	  break;
	case PRINT:
	    switch(s->info.node.arguments->elem->tag){
	    case str_ast:
            printf("%s\n", s->info.node.arguments->elem->info.string);
            break;
	    default:
            mod_v = eval_exp(s->info.node.arguments->elem, state->tbl, state->mem, &print);

            // Check if value is tainted
            if(mod_v.tainted == true) {
                printf("<secret>\n");
                taint_analysis(&print);
            } else {
                fprintf(stderr, "Tainted variable: None\n");
                printf("%u\n", mod_v.val);
            }
		break;
	    }

	  break;
	case IF:

	    if(eval_exp(s->info.node.arguments->elem, state->tbl, state->mem, &print).val){
		state = eval_stmts(s->info.node.arguments->next->elem, state);
	    } else {
		state = eval_stmts(s->info.node.arguments->next->next->elem, state);
            } 
	  break;
	case SEQ:
	    state = eval_stmts(s->info.node.arguments->next->elem, state);
	  break;
	case ASSERT:
	    if(eval_exp(s->info.node.arguments->elem, state->tbl,state->mem, &print).val ==0){
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

void taint_analysis(taint_list_t *list)
{
  fprintf(stderr, "Tainted variable: ");
  if(list == NULL) fprintf(stderr, "List is null\n");
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

