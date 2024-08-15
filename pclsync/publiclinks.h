/*
   Copyright (c) 2013-2014 pCloud Ltd.  All rights reserved.

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

#ifndef _PUBLIC_LINKS_H
#define _PUBLIC_LINKS_H

#include "psynclib.h"

int64_t do_psync_file_public_link(const char *path, int64_t *plinkid /*OUT*/,
                                  char **link /*OUT*/, char **err /*OUT*/,
                                  /*OUT*/ uint64_t expire, int maxdownloads,
                                  int maxtraffic);
int64_t do_psync_screenshot_public_link(const char *path, int hasdelay,
                                        uint64_t delay, char **link /*OUT*/,
                                        char **err /*OUT*/);
int64_t do_psync_folder_public_link(const char *path, char **link /*OUT*/,
                                    char **err /*OUT*/, uint64_t expire,
                                    int maxdownloads, int maxtraffic);
int64_t do_psync_folder_updownlink_link(int canupload,
                                        unsigned long long folderid,
                                        const char *mail, char **err /*OUT*/);
int64_t do_psync_folder_public_link_full(const char *path, char **link /*OUT*/,
                                         char **err /*OUT*/, uint64_t expire,
                                         int maxdownloads, int maxtraffic,
                                         const char *password);
int64_t do_psync_tree_public_link(const char *linkname, const char *root,
                                  char **folders, int numfolders, char **files,
                                  int numfiles, char **link /*OUT*/,
                                  char **err /*OUT*/, uint64_t expire,
                                  int maxdownloads, int maxtraffic);
plink_info_list_t *do_psync_list_links(char **err /*OUT*/);
int do_psync_delete_link(int64_t linkid, char **err /*OUT*/);
int64_t do_psync_upload_link(const char *path, const char *comment,
                             char **link /*OUT*/, char **err /*OUT*/,
                             uint64_t expire, int maxspace, int maxfiles);
int do_psync_delete_upload_link(int64_t uploadlinkid, char **err /*OUT*/);
int do_psync_change_link(unsigned long long linkid, unsigned long long expire,
                         int delete_expire, const char *linkpassword,
                         int delete_password, unsigned long long maxtraffic,
                         unsigned long long maxdownloads,
                         int enableuploadforeveryone,
                         int enableuploadforchosenusers, int disableupload,
                         char **err);

int do_change_link_expire(unsigned long long linkid, unsigned long long expire,
                          char **err);

int do_change_link_password(unsigned long long linkid, const char *password,
                            char **err);

int do_change_link_enable_upload(unsigned long long linkid,
                                 int enableuploadforeveryone,
                                 int enableuploadforchosenusers, char **err);

plink_contents_t *do_show_link(const char *code, char **err /*OUT*/);

void cache_links_all();
int cache_upload_links(char **err /*OUT*/);
int cache_links(char *err, size_t err_size /*OUT*/);

int do_delete_all_folder_links(psync_folderid_t folderid, char **err);
int do_delete_all_file_links(psync_fileid_t fileid, char **err);

int do_psync_change_link(unsigned long long linkid, unsigned long long expire,
                         int delete_expire, const char *linkpassword,
                         int delete_password, unsigned long long maxtraffic,
                         unsigned long long maxdownloads,
                         int enableuploadforeveryone,
                         int enableuploadforchosenusers, int disableupload,
                         char **err);
preciever_list_t *do_list_email_with_access(unsigned long long linkid,
                                            char **err);
int do_link_add_access(unsigned long long linkid, const char *mail, char **err);
int do_link_remove_access(unsigned long long linkid,
                          unsigned long long receiverid, char **err);
bookmarks_list_t *do_cache_bookmarks(char **err);
int do_remove_bookmark(const char *code, int locationid, char **err);
int do_change_bookmark(const char *code, int locationid, const char *name,
                       const char *description, char **err);
#endif //_PUBLIC_LINKS_H
