// debug/pnetlibs_debug.c - debug implementations for pnetlibs debug helpers

#include <stdio.h>

#include "papi.h"
#include "pdbg.h"
#include "plibs.h"
#include "pnetlibs.h"
#include "psock.h"

// --------------------------------------------------------------------------
// Internal helpers (debug-only)
// --------------------------------------------------------------------------

void pident(int ident) {
  VAR_ARRAY(b, char, ident + 1);
  memset(b, '\t', ident);
  b[ident] = 0;
  fputs(b, stdout);
}

static void print_tree(const binresult *tree, int ident) {
  int i;
  if (tree->type == PARAM_STR)
    printf("string(%u)\"%s\"", tree->length, tree->str);
  else if (tree->type == PARAM_NUM)
    printf("number %llu", (unsigned long long)tree->num);
  else if (tree->type == PARAM_DATA)
    printf("data %llu", (unsigned long long)tree->num);
  else if (tree->type == PARAM_BOOL)
    printf("bool %s", tree->num ? "true" : "false");
  else if (tree->type == PARAM_HASH) {
    printf("hash (%u){\n", tree->length);
    if (tree->length) {
      pident(ident + 1);
      printf("\"%s\" = ", tree->hash[0].key);
      print_tree(tree->hash[0].value, ident + 1);
      for (i = 1; i < tree->length; i++) {
        printf(",\n");
        pident(ident + 1);
        printf("\"%s\" = ", tree->hash[i].key);
        print_tree(tree->hash[i].value, ident + 1);
      }
    }
    printf("\n");
    pident(ident);
    printf("}");
  } else if (tree->type == PARAM_ARRAY) {
    printf("array (%u)[\n", tree->length);
    if (tree->length) {
      pident(ident + 1);
      print_tree(tree->array[0], ident + 1);
      for (i = 1; i < tree->length; i++) {
        printf(",\n");
        pident(ident + 1);
        print_tree(tree->array[i], ident + 1);
      }
    }
    printf("\n");
    pident(ident);
    printf("]");
  }
}

static void psync_apipool_dump_socket(psock_t *api) {
  binresult *res;
  res = papi_result(api);
  psync_apipool_release_bad(api);
  if (!res) {
    pdbg_logf(D_NOTICE, "could not read result from socket, it is probably broken");
    return;
  }
  pdbg_logf(D_WARNING, "read result from released socket, dumping and aborting");
  print_tree(res, 0);
  free(res);
  abort();
}

// --------------------------------------------------------------------------
// Strong override
// --------------------------------------------------------------------------

// Returns 1 if the release was handled (caller should return), 0 to proceed normally.
int pnetlibs_debug_check_apipool_release(psock_t *api) {
  if (unlikely(psock_readable(api))) {
    pdbg_logf(D_WARNING, "released socket with pending data to read");
    psync_apipool_dump_socket(api);
    return 1;
  }
  return 0;
}
