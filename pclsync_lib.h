/*
  Copyright (c) 2013-2015 pCloud Ltd.  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met: Redistributions of source code must retain the above
  copyright notice, this list of conditions and the following
  disclaimer.  Redistributions in binary form must reproduce the above
  copyright notice, this list of conditions and the following
  disclaimer in the documentation and/or other materials provided with
  the distribution.  Neither the name of pCloud Ltd nor the names of
  its contributors may be used to endorse or promote products derived
  from this software without specific prior written permission.

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

/*
  Dependencies:
  - <string>
  - pclsync_lib_c.h
*/

#ifndef PCLSYNC_LIB_H
#define PCLSYNC_LIB_H

struct pstatus_struct_;
typedef void (*status_callback_t)(int status, const char *stat_string);

namespace console_client {
namespace clibrary {

class pclsync_lib {
public:
  ~pclsync_lib();
  pclsync_lib();

  bool crypto_on_;
  bool save_pass_;
  bool setup_crypto_;
  pstatus_struct_ *status_;
  bool newuser_;
  status_callback_t status_callback_;
  bool was_init_;

  // Getters
  const std::string &get_username();
  const std::string &get_password();
  const std::string &get_crypto_pass();
  const std::string &get_mount();

  // Setters
  void set_username(const std::string &arg);
  void set_password(const std::string &arg);
  void set_crypto_pass(const std::string &arg);
  void set_mount(const std::string &arg);
  void set_savepass(bool s);
  void setupsetup_crypto(bool p);
  void set_newuser(bool p);
  void set_daemon(bool p);
  void set_status_callback(status_callback_t p);

  // Singleton
  static pclsync_lib &get_lib();

  // Console
  void get_pass_from_console();
  void get_cryptopass_from_console();

  // API calls
  int init();
  // std::string& username, std::string& password, std::string*
  // crypto_pass, int setup_crypto = 1, int usesrypto_userpass = 0);
  static int start_crypto(const char *pass, void **rep);
  static int stop_crypto(const char *path, void **rep);
  static int finalize(const char *path, void **rep);
  static int list_sync_folders(const char *path, void **rep);
  static int add_sync_folder(const char *path, void **rep);
  static int remove_sync_folder(const char *path, void **rep);

  char *get_token();
  int logout();
  int unlink();
  int login(const char *user, const char *pass, int save);

private:
  std::string username_;
  std::string password_;
  std::string crypto_pass_;
  std::string mount_;

  bool to_set_mount_;
  bool daemon_;

  void do_get_pass_from_console(std::string &password);
};
} // namespace clibrary
} // namespace console_client
#endif // PCLSYNC_LIB_H
