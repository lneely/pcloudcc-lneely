/*
   Copyright (c) 2015 Anton Titov.

   Copyright (c) 2015 pCloud Ltd.  All rights reserved.

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

#include "prunthrottled.h"
#include "plibs.h"
#include "ptimer.h"
#include "ptree.h"
#include "prun.h"


typedef struct {
  psync_tree tree;
  prun_throttle_cb call;
  const char *name;
  unsigned char scheduled;
} psync_rr_tree_node;

static pthread_mutex_t task_mutex = PTHREAD_MUTEX_INITIALIZER;
static psync_tree *tasks = PSYNC_TREE_EMPTY;

static void ratelimit_timer(psync_timer_t timer, void *ptr) {
  psync_rr_tree_node *node;
  const char *name;
  prun_throttle_cb call;
  int run;
  node = (psync_rr_tree_node *)ptr;
  pthread_mutex_lock(&task_mutex);
  if (node->scheduled) {
    run = 1;
    node->scheduled = 0;
    call = node->call;
    name = node->name;
  } else {
    run = 0;
    ptree_del(&tasks, &node->tree);
  }
  pthread_mutex_unlock(&task_mutex);
  if (run) {
    pdbg_logf(D_NOTICE, "running %s in a thread", name);
    prun_thread(name, call);
  } else {
    ptimer_stop(timer);
    free(node);
  }
}

void prun_throttled(const char *name, prun_throttle_cb call,
                           uint32_t minintervalsec, int runinthread) {
  psync_tree *tr, **addto;
  psync_rr_tree_node *node;
  int found;
  found = 0;
  pthread_mutex_lock(&task_mutex);
  tr = tasks;
  if (tr) {
    while (1) {
      node = ptree_element(tr, psync_rr_tree_node, tree);
      if (call < node->call) {
        if (tr->left)
          tr = tr->left;
        else {
          addto = &tr->left;
          break;
        }
      } else if (call > node->call) {
        if (tr->right)
          tr = tr->right;
        else {
          addto = &tr->right;
          break;
        }
      } else {
        found = 1;
        break;
      }
    }
  } else
    addto = &tasks;
  if (found) {
    if (node->scheduled)
      pdbg_logf(D_NOTICE, "skipping run of %s as it is already scheduled", name);
    else {
      pdbg_logf(D_NOTICE, "scheduling run of %s on existing timer", name);
      node->scheduled = 1;
    }
  } else {
    node = psync_new(psync_rr_tree_node);
    node->call = call;
    node->name = name;
    node->scheduled = 0;
    *addto = &node->tree;
    ptree_added_at(&tasks, tr, &node->tree);
  }
  pthread_mutex_unlock(&task_mutex);
  if (!found) {
    if (runinthread) {
      pdbg_logf(D_NOTICE, "running %s in a thread", name);
      prun_thread(name, call);
    } else {
      pdbg_logf(D_NOTICE, "running %s on this thread", name);
      call();
    }
    ptimer_register(ratelimit_timer, minintervalsec, node);
  }
}
