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

#include <cstring>
#include <iostream>
#include <string>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "pcryptofolder.h"
#include "prpc.h"
#include "psynclib.h"
#include "pshm.h"
#include "pdevice.h"
#include "pcommands.h"

#include "pclsync_lib.h"

namespace cc = console_client;
namespace clib = cc::clibrary;

static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

static const std::string client_name = "pCloud CC v3.0.0";

clib::pclsync_lib::pclsync_lib()
    : setup_crypto_(false), status_(new pstatus_struct_()), was_init_(false) {}

clib::pclsync_lib::~pclsync_lib() {}

const bool clib::pclsync_lib::get_trusted_device() { return trusted_device_; };

const std::string &clib::pclsync_lib::get_tfa_code() { return tfa_code_; }

const std::string &clib::pclsync_lib::get_username() { return username_; }

const std::string &clib::pclsync_lib::get_password() { return password_; }

const std::string &clib::pclsync_lib::get_crypto_pass() {
  return crypto_pass_;
};

const std::string &clib::pclsync_lib::get_mount() { return mount_; }

void clib::pclsync_lib::set_trusted_device(bool arg) {
  trusted_device_ = arg;
}
void clib::pclsync_lib::set_tfa_code(const std::string &arg) {
  tfa_code_ = arg;
}
void clib::pclsync_lib::set_username(const std::string &arg) {
  username_ = arg;
}
void clib::pclsync_lib::set_password(const std::string &arg) {
  password_ = arg;
}
void clib::pclsync_lib::set_crypto_pass(const std::string &arg) {
  crypto_pass_ = arg;
};
void clib::pclsync_lib::set_mount(const std::string &arg) { mount_ = arg; }
void clib::pclsync_lib::set_savepass(bool s) { save_pass_ = s; }
void clib::pclsync_lib::setupsetup_crypto(bool p) { setup_crypto_ = p; }
void clib::pclsync_lib::set_newuser(bool p) { newuser_ = p; }
void clib::pclsync_lib::set_daemon(bool p) { daemon_ = p; }
void clib::pclsync_lib::set_status_callback(status_callback_t p) {
  status_callback_ = p;
}

clib::pclsync_lib &clib::pclsync_lib::get_lib() {
  static clib::pclsync_lib g_lib;
  return g_lib;
}

char *clib::pclsync_lib::get_token() { return psync_get_token(); }

void clib::pclsync_lib::get_pass_from_console() {
  do_get_pass_from_console(password_);
}

void clib::pclsync_lib::get_tfa_code_from_console()
{
  if (daemon_) {
    std::cout << "Not able to read 2fa code when started as daemon." 
              << std::endl;
    exit(1);
  }
  std::cout << "Please enter 2fa code" 
            << std::endl;
  getline(std::cin, tfa_code_);
}

void clib::pclsync_lib::get_cryptopass_from_console() {
  do_get_pass_from_console(crypto_pass_);
}

void clib::pclsync_lib::do_get_pass_from_console(std::string &password) {
  if (daemon_) {
    std::cout << "Not able to read password when started as daemon."
              << std::endl;
    exit(1);
  }
  termios oldt;
  tcgetattr(STDIN_FILENO, &oldt);
  termios newt = oldt;
  newt.c_lflag &= ~ECHO;
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);
  std::cout << "Please, enter password" << std::endl;
  getline(std::cin, password);
  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
}

void event_handler(psync_eventtype_t event, psync_eventdata_t eventdata) {
  if (event < PEVENT_FIRST_USER_EVENT) {
    if (event & PEVENT_TYPE_FOLDER) {
      if (eventdata.folder) {
        std::cout << "folder event=" << event
                  << ", syncid=" << eventdata.folder->syncid
                  << ", folderid=" << eventdata.folder->folderid << ", name="
                  << (eventdata.folder->name ? eventdata.folder->name : "")
                  << ", local="
                  << (eventdata.folder->localpath ? eventdata.folder->localpath
                                                  : "")
                  << ", remote="
                  << (eventdata.folder->remotepath
                          ? eventdata.folder->remotepath
                          : "")
                  << std::endl;
      } else {
        std::cout << "folder event=" << event << " (no folder data)"
                  << std::endl;
      }
    } else {
      if (eventdata.file) {
        std::cout
            << "file event=" << event << ", syncid=" << eventdata.file->syncid
            << ", file=" << eventdata.file->fileid
            << ", name=" << (eventdata.file->name ? eventdata.file->name : "")
            << ", local="
            << (eventdata.file->localpath ? eventdata.file->localpath : "")
            << ", remote="
            << (eventdata.file->remotepath ? eventdata.file->remotepath : "")
            << std::endl;
      } else {
        std::cout << "file event=" << event << " (no file data)" << std::endl;
      }
    }
  } else if (event >= PEVENT_FIRST_SHARE_EVENT) {
    if (eventdata.share) {
      std::cout << "share event=" << event
                << ", folderid=" << eventdata.share->folderid << ", sharename="
                << (eventdata.share->sharename ? eventdata.share->sharename
                                               : "")
                << ", email="
                << (eventdata.share->toemail ? eventdata.share->toemail : "")
                << ", message="
                << (eventdata.share->message ? eventdata.share->message : "")
                << ", userid=" << eventdata.share->userid
                << ", shareid=" << eventdata.share->shareid
                << ", sharerequestid=" << eventdata.share->sharerequestid
                << ", created=" << eventdata.share->created
                << ", canread=" << eventdata.share->canread
                << ", cancreate=" << eventdata.share->cancreate
                << ", canmodify=" << eventdata.share->canmodify
                << ", candelete=" << eventdata.share->candelete << std::endl;
    } else {
      std::cout << "share event=" << event << " (no share data)" << std::endl;
    }
  } else {
    std::cout << "event " << event << std::endl;
  }
}

static int lib_setup_cripto() {
  const char *pwd = clib::pclsync_lib::get_lib().get_crypto_pass().c_str();

  if(pstatus_get(PSTATUS_TYPE_ONLINE) == PSTATUS_ONLINE_OFFLINE) {
    std::cout << "Cannot unlock crypto folder, pcloudcc is offline" << std::endl;
    return PSYNC_CRYPTO_CANT_CONNECT;
  }

  if(!psync_crypto_issetup()) {
    std::cout << "crypto is not setup, setting it up now..." << std::endl;
    if(int ret = pcryptofolder_setup(pwd, "no hint") != PSYNC_CRYPTO_SETUP_SUCCESS) {
      std::cout << "crypto setup failed, error code was " << ret << std::endl;
      return ret;
    }
    if(int ret = pcryptofolder_mkdir(0, "Crypto", NULL, NULL) != PSYNC_CRYPTO_SUCCESS) {
      std::cout << "failed to create crypto directory, error code was" << ret << std::endl;
      return ret;
    }
    std::cout << "crypto folder was setup using the provided password, "
      << "you may want to change your password hint on the "
      << "pcloud website." << std::endl;
  }

  if(int ret = pcryptofolder_unlock(pwd) != PSYNC_CRYPTO_START_SUCCESS) {
    std::cout << "Failed to unlock crypto folder: error code was " << ret << std::endl;
    return ret;
  }

  clib::pclsync_lib::get_lib().crypto_on_ = true;
  return 0;
}

static const char *status2string(uint32_t status) {
  switch (status) {
  case PSTATUS_READY:
    return "READY";
  case PSTATUS_DOWNLOADING:
    return "DOWNLOADING";
  case PSTATUS_UPLOADING:
    return "UPLOADING";
  case PSTATUS_DOWNLOADINGANDUPLOADING:
    return "DOWNLOADINGANDUPLOADING";
  case PSTATUS_LOGIN_REQUIRED:
    return "LOGIN_REQUIRED";
  case PSTATUS_BAD_LOGIN_DATA:
    return "BAD_LOGIN_DATA";
  case PSTATUS_BAD_LOGIN_TOKEN:
    return "BAD_LOGIN_TOKEN";
  case PSTATUS_ACCOUNT_FULL:
    return "ACCOUNT_FULL";
  case PSTATUS_DISK_FULL:
    return "DISK_FULL";
  case PSTATUS_PAUSED:
    return "PAUSED";
  case PSTATUS_STOPPED:
    return "STOPPED";
  case PSTATUS_OFFLINE:
    return "OFFLINE";
  case PSTATUS_CONNECTING:
    return "CONNECTING";
  case PSTATUS_SCANNING:
    return "SCANNING";
  case PSTATUS_USER_MISMATCH:
    return "USER_MISMATCH";
  case PSTATUS_ACCOUT_EXPIRED:
    return "ACCOUT_EXPIRED";
  case PSTATUS_TFA_REQUIRED:
    return "TFA_REQUIRED";
  case PSTATUS_BAD_TFA_CODE:
    return "BAD_TFA_CODE";
  default:
    return "Unrecognized status";
  }
}

static void status_change(pstatus_t *status) {
  static int cryptocheck = 0;

  char *err;
  err = (char *)psync_malloc(1024);

  std::cout << "Down: " << status->downloadstr << "| Up: " << status->uploadstr
            << ", status is " << status2string(status->status) << std::endl;
  *clib::pclsync_lib::get_lib().status_ = *status;
  if (status->status == PSTATUS_LOGIN_REQUIRED) {
    if (clib::pclsync_lib::get_lib().get_password().empty()) {
      clib::pclsync_lib::get_lib().get_pass_from_console();
    }

    psync_set_user_pass(clib::pclsync_lib::get_lib().get_username().c_str(),
                        clib::pclsync_lib::get_lib().get_password().c_str(),
                        (int)clib::pclsync_lib::get_lib().save_pass_);
    std::cout << "logging in" << std::endl;
  } else if (status->status == PSTATUS_TFA_REQUIRED) {
    if (clib::pclsync_lib::get_lib().get_tfa_code().empty()) {
      clib::pclsync_lib::get_lib().get_tfa_code_from_console();
    }

    psync_tfa_set_code(clib::pclsync_lib::get_lib().get_tfa_code().c_str(),
                       clib::pclsync_lib::get_lib().get_trusted_device(), 
                       0);
  } else if (status->status == PSTATUS_BAD_LOGIN_DATA) {
    if (!clib::pclsync_lib::get_lib().newuser_) {
      clib::pclsync_lib::get_lib().get_pass_from_console();
      psync_set_user_pass(clib::pclsync_lib::get_lib().get_username().c_str(),
                          clib::pclsync_lib::get_lib().get_password().c_str(),
                          (int)clib::pclsync_lib::get_lib().save_pass_);
    } else {
      std::cout << "registering" << std::endl;
      if (psync_register(clib::pclsync_lib::get_lib().get_username().c_str(),
                         clib::pclsync_lib::get_lib().get_password().c_str(), 1,
                         "bineapi.pcloud.com", 2, &err)) {
        std::cout << "both login and registration failed" << std::endl;
        exit(1);
      } else {
        std::cout << "registered, logging in" << std::endl;
        psync_set_user_pass(clib::pclsync_lib::get_lib().get_username().c_str(),
                            clib::pclsync_lib::get_lib().get_password().c_str(),
                            (int)clib::pclsync_lib::get_lib().save_pass_);
      }
    }
  }
  if (status->status == PSTATUS_READY || status->status == PSTATUS_UPLOADING ||
      status->status == PSTATUS_DOWNLOADING ||
      status->status == PSTATUS_DOWNLOADINGANDUPLOADING) {
    if (!cryptocheck) {
      cryptocheck = 1;
      if (clib::pclsync_lib::get_lib().setup_crypto_) {
        lib_setup_cripto();
      }
    }
    psync_fs_start();
  }
  if (clib::pclsync_lib::get_lib().status_callback_) {
    clib::pclsync_lib::get_lib().status_callback_(
        (int)status->status, status2string(status->status));
  }

  if (err)
    psync_free(err);
}

int clib::pclsync_lib::start_crypto(const char *pass) {
  get_lib().crypto_pass_ = pass;
  return lib_setup_cripto();
}

int clib::pclsync_lib::stop_crypto(const char *path) {
  (void)path;

  psync_crypto_stop();
  get_lib().crypto_on_ = false;
  return 0;
}

int clib::pclsync_lib::finalize(const char *path) {
  (void)path;

  psync_destroy();
  exit(0);
}

// path is the local and remote path delimited by '|'
int clib::pclsync_lib::add_sync_folder(const char *path) {
  if (path == nullptr) {
    std::cerr << "Error: path is nullptr" << std::endl;
    return -255;
  }
  const char delimiter = '|';
  std::string combined(path);
  size_t delimiter_pos = combined.find(delimiter);
  if (delimiter_pos == std::string::npos) {
    std::cerr << "Error: Invalid path format. Expected 'localpath|remotepath'"
              << std::endl;
    return -255;
  }

  std::string localpath = combined.substr(0, delimiter_pos);
  std::string remotepath = combined.substr(delimiter_pos + 1);
  psync_syncid_t syncid = psync_add_sync_by_path(localpath.c_str(), remotepath.c_str(), PSYNC_FULL);

  pthread_mutex_lock(&mtx);
  if (syncid == PSYNC_INVALID_SYNCID) {
      std::cerr << "psync_add_sync_by_path returned PSYNC_INVALID_SYNCID" << std::endl;
      uint64_t error_value = (static_cast<uint64_t>(1) << 32) | PSYNC_INVALID_SYNCID;
      pshm_write(&error_value, sizeof(uint64_t));
      pthread_mutex_unlock(&mtx);
      return -1;
  }
  pshm_write(&syncid, sizeof(psync_syncid_t));
  pthread_mutex_unlock(&mtx);
  return 0;
}

// path is the folderid to remove
int clib::pclsync_lib::remove_sync_folder(const char *path) {
  psync_folderid_t folderid;
  folderid = static_cast<psync_folderid_t>(std::stoull(path, nullptr, 10));
  return psync_delete_sync_by_folderid(folderid);
}

// path is not used
int clib::pclsync_lib::list_sync_folders(const char *path) {
  (void)path;

  psync_folder_list_t *folders;
  size_t folderssz;

  folders = psync_get_sync_list();
  if (!folders) {
    return -1;
  }
  folderssz =
      sizeof(psync_folder_list_t) + (folders->foldercnt * sizeof(psync_folder_t));

  pthread_mutex_lock(&mtx);
  pshm_write(folders, folderssz);
  pthread_mutex_unlock(&mtx);

  psync_free(folders);

  return 0;
}

int clib::pclsync_lib::init() {
  std::string software_string;
  char *username_old;

  pdevice_set_software(client_name.c_str());

  if (setup_crypto_ && crypto_pass_.empty()) {
    return 3;
  }

  if (psync_init()) {
    std::cout << "init failed\n";
    return 1;
  }

  was_init_ = true;

  if (!get_mount().empty()) {
    psync_set_string_setting("fsroot", get_mount().c_str());
  }

  psync_start_sync(status_change, event_handler);

  username_old = psync_get_username();
  if (username_old) {
    if (username_.compare(username_old) != 0) {
      std::cout << "logged in with user " << username_old << ", not "
                << username_ << ", unlinking" << std::endl;
      psync_unlink();
      psync_free(username_old);
      return 2;
    }
    psync_free(username_old);
  }

  psync_overlay_register_callback(STARTCRYPTO, &clib::pclsync_lib::start_crypto);
  psync_overlay_register_callback(STOPCRYPTO, &clib::pclsync_lib::stop_crypto);
  psync_overlay_register_callback(FINALIZE, &clib::pclsync_lib::finalize);
  psync_overlay_register_callback(LISTSYNC, &clib::pclsync_lib::list_sync_folders);
  psync_overlay_register_callback(ADDSYNC, &clib::pclsync_lib::add_sync_folder);
  psync_overlay_register_callback(STOPSYNC, &clib::pclsync_lib::remove_sync_folder);

  return 0;
}

int clib::pclsync_lib::login(const char *user, const char *pass, int save) {
  set_username(user);
  set_password(pass);
  set_savepass(bool(save));
  psync_set_user_pass(user, pass, save);
  return 0;
}

int clib::pclsync_lib::logout() {
  set_password("");
  psync_logout();
  return 0;
}

int clib::pclsync_lib::unlink() {
  set_username("");
  set_password("");
  psync_unlink();
  return 0;
}
