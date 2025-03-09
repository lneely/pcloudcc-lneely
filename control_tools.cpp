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
#include <readline/readline.h>
#include <readline/history.h>

#include "pclsync_lib.h"
#include "pclsync/pshm.h"
#include "pclsync/pfoldersync.h"
#include "pclsync/pcommands.h"

#include "rpcclient.h"
#include "CLI11.hpp"

namespace cc = console_client;

namespace control_tools {

static char* command_generator(const char* text, int state) {
  static int list_index, len;
  static const char* commands[] = {
    "help", "?",
    "crypto", "crypto start", "crypto stop", 
    "c", "c start", "c stop",
    "sync", "sync ls", "sync add", "sync remove", "sync rm",
    "s", "s ls", "s add", "s remove", "s rm",
    "finalize", "f",
    "quit", "q",
    nullptr
  };

  if (!state) {
    list_index = 0;
    len = strlen(text);
  }

  while (const char* command = commands[list_index++]) {
    if (strncmp(command, text, len) == 0) {
      return strdup(command); // Caller frees this with free()
    }
  }
  
  return nullptr;
}

static char** command_completion(const char* text, int start, int end) {
  if (start == 0) {
    return rl_completion_matches(text, command_generator);
  }
  return nullptr;
}

void setup_app(CLI::App *app) {
  app->fallthrough();
  app->footer("Type 'help' or '?' for a list of supported commands.");

  // top-level commands
  app->add_subcommand("help", "Show help")->alias("?")->callback([] {
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
  });
  auto crypto_cmd = app->add_subcommand("crypto", "Crypto-related commands")->alias("c");
  crypto_cmd->require_subcommand();
  auto sync_cmd = app->add_subcommand("sync", "Sync-related commands")->alias("s");
  sync_cmd->require_subcommand();

  // finalize command
  app->add_subcommand("finalize", "Finalize and exit")->alias("f")->callback([] {
    char *errm = NULL;
    size_t errm_size = 0;
    RpcClient *rpc = new RpcClient();
    rpc->Call(FINALIZE, "", &errm, &errm_size);
    delete rpc;
    std::cout << "Exiting ..." << std::endl;
    if (errm) { free(errm); }
    exit(0);
  });

  app->add_subcommand("quit", "Quit the program")->alias("q")->callback([] {
    exit(0);
  });

  // crypto start
  auto start_crypto_cmd = crypto_cmd->add_subcommand("start", "Start crypto");
  static std::string start_crypto_pwd;
  start_crypto_cmd->add_option("password", start_crypto_pwd, "Crypto password")->required();
  start_crypto_cmd->callback([] { 
    char *errm = NULL;
    size_t errm_size = 0;
    RpcClient *rpc = new RpcClient();
    if(int result = rpc->Call(STARTCRYPTO, start_crypto_pwd.c_str(), &errm, &errm_size) != 0) {
      std::cout << "Start Crypto failed: " << (errm ? errm : "no message") << std::endl;
      if (errm) { free(errm); }
      delete rpc;
      return result;
    }
    delete rpc;
    std::cout << "Crypto started." << std::endl;
    if (errm) { free(errm); }
    return 0;
  });

  // crypto stop
  crypto_cmd->add_subcommand("stop", "Stop crypto")->callback([] {
    char *errm = NULL;
    size_t errm_size = 0;
    RpcClient *rpc = new RpcClient();
    if(int result = rpc->Call(STOPCRYPTO, "", &errm, &errm_size) != 0) {
      std::cout << "Stop Crypto failed: "<< (errm ? errm : "no message") << std::endl;
      if (errm) { free(errm); }
      delete rpc;
      return result;
    }
    delete rpc;
    std::cout << "Crypto Stopped." << std::endl;  
    if (errm) { free(errm); }
    return 0;
  });

  // sync list
  sync_cmd->add_subcommand("list", "List sync folders")->alias("ls")->callback([] {
    char *errm = NULL;
    size_t errmsz = 0;
    RpcClient *rpc = new RpcClient();

    if(int result = rpc->Call(LISTSYNC, "", &errm, &errmsz) != 0) {
      std::cout << "List Sync Folders failed: " << (errm ? errm : "no message") << std::endl;
      if (errm) { free(errm); }
      delete rpc;
      return result;
    } 
    delete rpc;

    psync_folder_list_t *flist = NULL;
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
          psync_folder_t *folder = &flist->folders[i];
          std::cout << std::left << std::setw(id_width) << folder->folderid
                    << std::setw(path_width) << folder->localpath
                    << std::setw(path_width) << folder->remotepath << std::endl;
        }
      } else {
        std::cout << "No synchronized folders found." << std::endl;
      }
      if(flist) { free(flist); }
    } else {
      std::cout << "failed to read folder list from shm" << std::endl;
      if(flist) { free(flist); }
      return -1;
    }
    if(errm) { free(errm); }
    return 0;
  });

  // sync add
  auto sync_add_cmd = sync_cmd->add_subcommand("add", "Add sync folder");
  static std::string localpath, remotepath;
  sync_add_cmd->add_option("localpath", localpath, "Local Path")->required();
  sync_add_cmd->add_option("remotepath", remotepath, "Remote Path")->required();
  sync_add_cmd->callback([] {
    char *errm = NULL;
    size_t errmsz = 0;

    std::string combinedPaths = localpath + '|' + remotepath;
    RpcClient *rpc = new RpcClient();
    if(int result = rpc->Call(ADDSYNC, combinedPaths.c_str(), &errm, &errmsz) != 0) {      
      if (result == -1) {
        std::cout << "Add Sync Folders failed: remote folder " << remotepath << " not found." << std::endl;
      } else {
        std::cout << "Add Sync Folders failed:" << (errm ? errm : "no message") << std::endl;
      }
      if (errm) { free(errm); }
      delete rpc;
      return result;
    }
    delete rpc;
    if(errm) { free(errm); }
    return 0;
  });

  // sync remove
  auto sync_remove_cmd = sync_cmd->add_subcommand("remove", "Remove sync folder (use ls to get folder ID)")->alias("rm");
  static std::string syncrm_fid;
  sync_remove_cmd->add_option("folderid", syncrm_fid, "Folder ID")->required();
  sync_remove_cmd->callback([] {
    char *errm = NULL;
    size_t errmsz = 0;
    const char *folderid = syncrm_fid.c_str();

    RpcClient *rpc = new RpcClient();
    if(int result = rpc->Call(STOPSYNC, folderid, &errm, &errmsz) != 0) {
      std::cout << "Remove Sync Folder failed: " << (errm ? errm : "no message") << std::endl;
      if (errm) { free(errm); }
      delete rpc;
      return result;
    }
    delete rpc;
    std::cout << "Successfully removed sync folder with folderid " << folderid << std::endl;
    
    if(errm) { free(errm); }
    return 0;
  });
}

int process_command(const std::string &command) {
  CLI::App app = CLI::App{"pcloudcc-lneely"};
  setup_app(&app);
  try {
    app.parse(command);
    return 0;
  } catch (const CLI::ParseError &e) {
    std::cerr << "Invalid command: '" << command << "'" << std::endl;
    return 1;
  }
}

void process_commands() {
  CLI::App app = CLI::App{"pcloudcc-lneely"};
  setup_app(&app);

  // enable command history and auto-completion
  using_history();
  rl_attempted_completion_function = command_completion;

  // command loop
  while (true) {
    char* line_read = readline("pcloud> ");
    if (!line_read) break;
    if (line_read[0]) {
      add_history(line_read);
    }
    std::string line(line_read);
    free(line_read); 

    try {
      app.parse(line);
    } catch (const CLI::ParseError &e) {
      std::vector<std::string> args;
      std::istringstream iss(line);
      std::string arg;
      std::ostringstream invs;

      while (iss >> arg) {
        args.push_back(arg);
      }

      invs  << "Invalid command: '" << line 
            << "'. Type 'help' or '?' to get a list of valid commands.";
      if (!args.empty()) {
        try {
          auto *subcom = app.get_subcommand(args[0]);
          if (subcom) {
            std::cout << "Usage for '" << args[0] << "':" << std::endl;
            std::cout << subcom->help() << std::endl;
          } else {
            std::cout << invs.str() << std::endl;
          }
        } catch (...) {
          std::cout << invs.str() << std::endl;
        }
      } else {
        std::cout << invs.str() << std::endl;
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
