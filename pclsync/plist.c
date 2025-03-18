/*
   Copyright (c) 2014 Anton Titov.

   Copyright (c) 2014 pCloud Ltd.  All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met: Redistributions of source code must retain the above
   copyright notice, this list of conditions and the following
   disclaimer.  Redistributions in binary form must reproduce the
   above copyright notice, this list of conditions and the following
   disclaimer in the documentation and/or other materials provided
   with the distribution.  Neither the name of pCloud Ltd nor the
   names of its contributors may be used to endorse or promote
   products derived from this software without specific prior written
   permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
   FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL pCloud
   Ltd BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
   OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
   USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
   DAMAGE.
*/

#include <stdlib.h>
#include <string.h>

#include "plist.h"
#include "pdbg.h"

/* Fairly simple in-place merge sort with constant storage requirements.
 *
 * Recursive approach might would use O(log N) storage on the stack but may
 * have better cache locality for lists that do not fit in processor cache,
 * may benefit from precise in-half splitting and can go without needless
 * iterating of the list to reach the half of it.
 */

void psync_list_sort(psync_list *l, psync_list_compare cmp) {
  psync_list *ls, *l1, *l2, **tail;
  unsigned long depth, cnt, i, l1len, l2len;
  if (psync_list_isempty(l))
    return;
  ls = l->next;
  l->prev->next = NULL;
  depth = 1;
  while (1) {
    l1 = ls;
    tail = &ls;
    cnt = 0;
    while (l1) {
      cnt++;
      l2 = l1;
      for (i = 0; i < depth && l2; i++)
        l2 = l2->next;
      if (!l2) {
        *tail = l1;
        goto nol2;
      }
      l1len = i;
      l2len = depth;
      while (1) {
        if (cmp(l1, l2) <= 0) {
          l1len--;
          *tail = l1;
          tail = &l1->next;
          if (!l1len)
            goto l1fin;
          l1 = l1->next;
        } else {
          l2len--;
          *tail = l2;
          tail = &l2->next;
          l2 = l2->next;
          if (!l2len || !l2)
            goto l2fin;
        }
      }
    l2fin:
      *tail = l1;
      for (i = 0; i < l1len - 1; i++)
        l1 = l1->next;
      tail = &l1->next;
      l1 = l2;
      continue;
    l1fin:
      *tail = l2;
      for (i = 0; l2->next && i < l2len - 1; i++)
        l2 = l2->next;
      tail = &l2->next;
      l1 = l2->next;
    }
    *tail = NULL;
  nol2:
    if (cnt <= 1)
      break;
    depth *= 2;
  }
  l->next = ls;
  l1 = l;
  while (ls) {
    ls->prev = l1;
    l1 = ls;
    ls = ls->next;
  }
  l1->next = l;
  l->prev = l1;
}

void psync_list_extract_repeating(psync_list *l1, psync_list *l2, psync_list *extracted1, psync_list *extracted2, psync_list_compare cmp) {
  psync_list *li1, *li2, *ln1, *ln2;
  int cr;
  psync_list_sort(l1, cmp);
  psync_list_sort(l2, cmp);
  li1 = l1->next;
  li2 = l2->next;
  while (li1 != l1 && li2 != l2) {
    cr = cmp(li1, li2);
    if (cr < 0)
      li1 = li1->next;
    else if (cr > 0)
      li2 = li2->next;
    else {
      ln1 = li1->next;
      ln2 = li2->next;
      psync_list_del(li1);
      psync_list_add_tail(extracted1, li1);
      psync_list_del(li2);
      psync_list_add_tail(extracted2, li2);
      li1 = ln1;
      li2 = ln2;
    }
  }
}

psync_list_builder_t *psync_list_builder_create(size_t element_size, size_t offset) {
  psync_list_builder_t *builder;
  builder = malloc(sizeof(psync_list_builder_t));
  builder->element_size = element_size;
  builder->elements_offset = offset;
  if (element_size <= 200)
    builder->elements_per_list = 40;
  else
    builder->elements_per_list = 12;
  builder->cnt = 0;
  builder->stringalloc = 0;
  psync_list_init(&builder->element_list);
  builder->last_elements = NULL;
  psync_list_init(&builder->string_list);
  builder->last_strings = NULL;
  psync_list_init(&builder->number_list);
  builder->last_numbers = NULL;
  return builder;
}

uint32_t *psync_list_bulder_push_num(psync_list_builder_t *builder) {
  if (!builder->last_numbers ||
      builder->last_numbers->used >=
          sizeof(builder->last_numbers->numbers) / sizeof(uint32_t)) {
    psync_list_num_list *l = malloc(sizeof(psync_list_num_list));
    l->used = 0;
    builder->last_numbers = l;
    psync_list_add_tail(&builder->number_list, &l->list);
  }
  return &builder->last_numbers->numbers[builder->last_numbers->used++];
}

uint32_t psync_list_bulder_pop_num(psync_list_builder_t *builder) {
  uint32_t ret;
  ret = builder->last_numbers->numbers[builder->popoff++];
  if (builder->popoff >= builder->last_numbers->used) {
    builder->last_numbers = psync_list_element(builder->last_numbers->list.next,
                                               psync_list_num_list, list);
    builder->popoff = 0;
  }
  return ret;
}


void *psync_list_bulder_add_element(psync_list_builder_t *builder) {
  if (!builder->last_elements ||
      builder->last_elements->used >= builder->elements_per_list) {
    builder->last_elements = (psync_list_element_list *)malloc(
        offsetof(psync_list_element_list, elements) +
        builder->element_size * builder->elements_per_list);
    psync_list_add_tail(&builder->element_list, &builder->last_elements->list);
    builder->last_elements->used = 0;
  }
  builder->current_element =
      builder->last_elements->elements +
      builder->last_elements->used * builder->element_size;
  builder->cstrcnt = psync_list_bulder_push_num(builder);
  *builder->cstrcnt = 0;
  builder->last_elements->used++;
  builder->cnt++;
  return builder->current_element;
}

void psync_list_add_lstring_offset(psync_list_builder_t *builder, size_t offset, size_t length) {
  char **str, *s;
  psync_list_string_list *l;
  length++;
  str = (char **)(builder->current_element + offset);
  builder->stringalloc += length;
  if (unlikely(length > 2000)) {
    l = (psync_list_string_list *)malloc(sizeof(psync_list_string_list) +
                                               length);
    s = (char *)(l + 1);
    psync_list_add_tail(&builder->string_list, &l->list);
  } else if (!builder->last_strings || builder->last_strings->next + length >
                                           builder->last_strings->end) {
    l = (psync_list_string_list *)malloc(sizeof(psync_list_string_list) +
                                               4000);
    s = (char *)(l + 1);
    l->next = s + length;
    l->end = s + 4000;
    psync_list_add_tail(&builder->string_list, &l->list);
    builder->last_strings = l;
  } else {
    s = builder->last_strings->next;
    builder->last_strings->next += length;
  }
  memcpy(s, *str, length);
  *str = s;
  *(psync_list_bulder_push_num(builder)) = offset;
  *(psync_list_bulder_push_num(builder)) = length;
  (*builder->cstrcnt)++;
}

void psync_list_add_string_offset(psync_list_builder_t *builder,
                                  size_t offset) {
  psync_list_add_lstring_offset(
      builder, offset, strlen(*((char **)(builder->current_element + offset))));
}

void *psync_list_builder_finalize(psync_list_builder_t *builder) {
  char *ret, *elem, *str;
  char **pstr;
  psync_list_element_list *el;
  unsigned long i;
  uint32_t j, scnt, offset, length;
  size_t sz;
  sz = builder->elements_offset + builder->element_size * builder->cnt +
       builder->stringalloc;
  pdbg_logf(D_NOTICE, "allocating %lu bytes, %lu of which for strings",
        (unsigned long)sz, (unsigned long)builder->stringalloc);
  ret = malloc(sizeof(char) * sz);
  if (builder->elements_offset <= sizeof(builder->cnt))
    memcpy(ret, &builder->cnt, builder->elements_offset);
  else
    memcpy(ret, &builder->cnt, sizeof(builder->cnt));
  elem = ret + builder->elements_offset;
  str = elem + builder->element_size * builder->cnt;

  builder->last_numbers =
      psync_list_element(builder->number_list.next, psync_list_num_list, list);
  builder->popoff = 0;

  psync_list_for_each_element(el, &builder->element_list,
                              psync_list_element_list, list) {
    for (i = 0; i < el->used; i++) {
      memcpy(elem, el->elements + (i * builder->element_size),
             builder->element_size);
      scnt = psync_list_bulder_pop_num(builder);
      for (j = 0; j < scnt; j++) {
        offset = psync_list_bulder_pop_num(builder);
        length = psync_list_bulder_pop_num(builder);
        pstr = (char **)(elem + offset);
        memcpy(str, *pstr, length);
        *pstr = str;
        str += length;
      }
      elem += builder->element_size;
    }
  }

  psync_list_for_each_element_call(&builder->element_list, psync_list_element_list, list, free);
  psync_list_for_each_element_call(&builder->string_list, psync_list_string_list, list, free);
  psync_list_for_each_element_call(&builder->number_list, psync_list_num_list, list, free);
  free(builder);
  return ret;
}

