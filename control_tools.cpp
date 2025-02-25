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
#include <iomanip>
#include <iostream>
#include <string>

#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include "control_tools.h"
#include "pclsync/overlay_client.h"

#include "pclsync_lib.h"
#include "pclsync/psynclib.h"
#include "pclsync/pshm.h"

#include "CLI11.hpp"

namespace cc = console_client;

namespace control_tools {

static const int STOP = 0;

enum command_ids_ {
  STARTCRYPTO = 20,
  STOPCRYPTO,
  FINALIZE,
  LISTSYNC,
  ADDSYNC,
  STOPSYNC
};

int list_sync_folders() {
  int ret;
  char *errm;
  size_t errmsz;
  int result;
  psync_folder_list_t *flist;
  psync_folder_t *folder;
  int rval;

  errm = NULL;
  errmsz = 0;
  rval = 0;

  result = SendCall(LISTSYNC, "", &ret, &errm, &errmsz);

  if (result != 0) {
    std::cout << "List Sync Folders failed. return is " << ret
              << " and message is " << (errm ? errm : "no message")
              << std::endl;
    rval = result;
  } 

  if(pshm_read((void**)&flist, NULL)) {
    const int id_width = 12;
    const int path_width = 30;

    if(flist->foldercnt > 0) {
      std::cout << std::left << std::setw(id_width) << "Folder ID"
                << std::setw(path_width) << "Local Path"
                << std::setw(path_width) << "Remote Path" << std::endl;
      std::cout << std::string(id_width, '-')
                << std::string(path_width - 1, '-')
                << std::string(path_width - 1, '-') << std::endl;
      for (uint32_t i = 0; i < flist->foldercnt; i++) {
        folder = &flist->folders[i];
        std::cout << std::left << std::setw(id_width) << folder->folderid
                  << std::setw(path_width) << folder->localpath
                  << std::setw(path_width) << folder->remotepath << std::endl;
      }
    } else {
      std::cout << "No synchronized folders found." << std::endl;
      rval = ret;
    }
    rval = ret;

    free(flist);
  } else {
    std::cout << "failed to read folder list from shm" << std::endl;
    return -1;
  }

  if(errm) {
      free(errm);
  }

  return rval;
}

int start_crypto(const char *pass) {
  int ret;
  char *errm;
  size_t errm_size;

  int result = SendCall(STARTCRYPTO, pass, &ret, &errm, &errm_size);

  if (result != 0 || ret != 0) {
    std::cout << "Start Crypto failed. return is " << ret << " and message is "
              << (errm ? errm : "no message") << std::endl;
  } else {
    std::cout << "Crypto started. " << std::endl;
  }
  if (errm)
    free(errm);
  return ret;
}

int stop_crypto() {
  int ret;
  char *errm;
  size_t errm_size;

  int result = SendCall(STOPCRYPTO, "", &ret, &errm, &errm_size);
  if (result != 0) {
    std::cout << "Stop Crypto failed. return is " << ret << " and message is "
              << (errm ? errm : "no message") << std::endl;
  } else {
    std::cout << "Crypto Stopped. " << std::endl;
  }

  if (errm)
    free(errm);
  return ret;
}

int remove_sync_folder(const char *folderid) {
  int ret;
  char *errm;
  size_t errmsz;
  int result;
  int rval;

  errm = NULL;
  errmsz = 0;
  rval = 0;

  result = SendCall(STOPSYNC, folderid, &ret, &errm, &errmsz);
  if (result != 0) {
    std::cout << "Remove Sync Folder failed with unknown error. return is "
              << ret << " and message is " << (errm ? errm : "no message")
              << std::endl;
    rval = result;
  } else {
    std::cout << "Successfully removed sync folder with folderid " << folderid
              << std::endl;
  }

  if(errm) {
      free(errm);
  }
  return rval;
}

// TODO: should add support for specifying sync type. Need a better
// CLI processing solution first.
int add_sync_folder(std::string localpath, std::string remotepath) {
  int ret;
  char *errm;
  size_t errmsz;
  int result;
  int rval;

  errm = NULL;
  errmsz = 0;
  rval = 0;

  std::string combinedPaths = localpath + '|' + remotepath;
  result = SendCall(ADDSYNC, combinedPaths.c_str(), &ret, &errm, &errmsz);

  if (result != 0) {
    if (result == -1) {
      std::cout << "Add Sync Folders failed: remote folder " << remotepath
                << " not found." << std::endl;
    } else {
      std::cout << "Add Sync Folders failed with unknown error. return is "
                << ret << " and message is " << (errm ? errm : "no message")
                << std::endl;
    }
    rval = result;
  } else {
    rval = ret;
  }

  if(errm) {
      free(errm);
  }

  return rval;
}

int finalize() {
  int ret;
  char *errm;
  size_t errm_size;

  SendCall(FINALIZE, "", &ret, &errm, &errm_size);
  std::cout << "Exiting ..." << std::endl;

  if (errm){
      free(errm);
  }

  return ret;
}

void help() {
  std::cout << "Supported commands are:" << std::endl
            << "  help(?): Show this help message" << std::endl
            << "  crypto(c):" << std::endl
            << "    start <crypto pass>: Unlock crypto folder" << std::endl
            << "    stop: Lock crypto folder" << std::endl
            << "  sync(s):" << std::endl
            << "    list(ls): List sync folders" << std::endl
            << "    add <localpath> <remotepath>: Add sync folder" << std::endl
            << "    remove(rm) <folderid>: Remove sync folder" << std::endl
            << "  finalize(f): Kill daemon and quit" << std::endl
            << "  quit(q): Exit this program" << std::endl;
}

void process_commands() {
  CLI::App app{"pcloudcc-lneely"};
  app.fallthrough();
  app.footer("Type 'help' or '?' for a list of supported commands.");

  // top-level commands
  app.add_subcommand("help", "Show help")->alias("?")->callback(help);
  auto crypto_cmd =
      app.add_subcommand("crypto", "Crypto-related commands")->alias("c");
  crypto_cmd->require_subcommand();
  auto sync_cmd =
      app.add_subcommand("sync", "Sync-related commands")->alias("s");
  sync_cmd->require_subcommand();
  app.add_subcommand("finalize", "Finalize and exit")->alias("f")->callback([] {
    finalize();
    exit(0);
  });
  app.add_subcommand("quit", "Quit the program")->alias("q")->callback([] {
    exit(0);
  });

  // crypto subcommands
  auto start_crypto_cmd = crypto_cmd->add_subcommand("start", "Start crypto");
  std::string start_crypto_pwd;
  start_crypto_cmd->add_option("password", start_crypto_pwd, "Crypto password")
      ->required();
  start_crypto_cmd->callback([&] { start_crypto(start_crypto_pwd.c_str()); });

  crypto_cmd->add_subcommand("stop", "Stop crypto")->callback(stop_crypto);

  // sync subcommands
  sync_cmd->add_subcommand("list", "List sync folders")
      ->alias("ls")
      ->callback(list_sync_folders);

  auto sync_add_cmd = sync_cmd->add_subcommand("add", "Add sync folder");
  std::string syncadd_lpath, syncadd_rpath;
  sync_add_cmd->add_option("localpath", syncadd_lpath, "Local Path")->required();
  sync_add_cmd->add_option("remotepath", syncadd_rpath, "Remote Path")->required();
  sync_add_cmd->callback([&] {
    add_sync_folder(syncadd_lpath, syncadd_rpath);
  });

  auto sync_remove_cmd =
      sync_cmd->add_subcommand("remove", "Remove sync folder (use ls to get folder ID)")->alias("rm");
  std::string syncrm_fid;
  sync_remove_cmd->add_option("folderid", syncrm_fid, "Folder ID")->required();
  sync_remove_cmd->callback([&] { remove_sync_folder(syncrm_fid.c_str()); });

  // command loop
  while (true) {
    std::cout << "pcloud> ";
    std::string line;
    if (!std::getline(std::cin, line))
      break;
    try {
      app.parse(line);
    } catch (const CLI::ParseError &e) {
      std::vector<std::string> args;
      std::istringstream iss(line);
      std::string arg;
      while (iss >> arg) {
        args.push_back(arg);
      }

      if (!args.empty()) {
        try {
          auto *subcom = app.get_subcommand(args[0]);
          if (subcom) {
            std::cout << "Usage for '" << args[0] << "':" << std::endl;
            std::cout << subcom->help() << std::endl;
          } else {
            std::cout
                << "Invalid command: '" << line
                << "'. Type 'help' or '?' to get a list of valid commands."
                << std::endl;
          }
        } catch (...) {
          std::cout << "Invalid command: '" << line
                    << "'. Type 'help' or '?' to get a list of valid commands."
                    << std::endl;
        }
      } else {
        std::cout << "Invalid command: '" << line
                  << "'. Type 'help' or '?' to get a list of valid commands."
                  << std::endl;
      }
    }
  }
}

int daemonize(bool do_commands) {
  pid_t pid, sid;

  pid = fork();
  if (pid < 0) {
    exit(EXIT_FAILURE);
  } else if (pid > 0) {
    std::cout << "Daemon process created. Process id is: " << pid << std::endl;
    if (do_commands) {
      process_commands();
    } else {
      std::cout << "kill -9 " << pid << std::endl
                << " to stop it." << std::endl;
    }
    exit(EXIT_SUCCESS);
  }

  /* Open any logs here */
  umask(0);
  sid = setsid();
  if (sid < 0) {
    exit(EXIT_FAILURE);
  }

  if ((chdir("/")) < 0) {
    exit(EXIT_FAILURE);
  }

  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);

  if (cc::clibrary::pclsync_lib::get_lib().init()) {
    exit(EXIT_FAILURE);
  }

  while (1) {
    sleep(10);
  }
}

} // namespace control_tools
