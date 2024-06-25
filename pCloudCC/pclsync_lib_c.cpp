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

#include "pclsync_lib_c.h"
#include "pclsync_lib.h"

#ifdef __cplusplus
extern "C" {
#endif

  namespace cc = console_client::clibrary;
 
  int 
  init() {
	if (!cc::pclsync_lib::get_lib().was_init_)
	  return cc::pclsync_lib::get_lib().init();
	else return 0;
  }

  int 
  start_crypto (const char* pass) {
	return cc::pclsync_lib::start_crypto (pass, NULL);
  }
  int 
  stop_crypto () {
	return cc::pclsync_lib::stop_crypto (NULL, NULL);
  }
  int 
  finalize () { 
	return cc::pclsync_lib::finalize(NULL, NULL);
  }
  void 
  set_status_callback(status_callback_t c) {
	cc::pclsync_lib::get_lib().set_status_callback(c);
  }

  char* 
  get_token(){
	return cc::pclsync_lib::get_lib().get_token();
  }

  int 
  login(const char* user, const char* pass, int save) {
	return cc::pclsync_lib::get_lib().login(user, pass, save);
  }

  int 
  logout() {
	return cc::pclsync_lib::get_lib().logout();
  }

  int 
  unlinklib() {
	return cc::pclsync_lib::get_lib().unlink();
  }

#ifdef __cplusplus
}
#endif
