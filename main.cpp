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
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <unistd.h>

#include "CLI11.hpp"

#include "control_tools.h"

#include "pclsync_lib.h"
#include "pclsync/psettings.h"
#include "pclsync/psignal.h"
#include "pclsync/putil.h"

namespace ct = control_tools;
namespace cc = console_client;

// TODO: a proper version string might be useful for debugging
static std::string version = "git-lneely";

int main(int argc, char **argv) {
  psignal_register(SIGSEGV);
  psignal_register(SIGABRT);
  psignal_register(SIGBUS);

  std::cout << "pCloud console client (" << version << ")" << std::endl;
  std::string username = "";
  std::string tfa_code = "";
  bool daemon = false;
  bool commands = false;
  bool commands_only = false;
  bool newuser = false;
  bool passwordsw = false;
  bool save_pass = false;
  bool crypto = false;
  bool passascrypto_sw = false;
  bool trusted_device = false;
  std::string mountpoint = "";
  uint64_t cache_size_gb = 0;
  std::string log_path = "";
  std::string log_level = "";
  std::string fs_event_log = "";
  std::string fuse_opts = "";

  CLI::App app{"Allowed options"};
  app.set_help_flag("-h,--help", "Show this help message.");
  
  app.add_option("-u,--username", username, "pCloud account name.")
    ->envname("PCLOUD_USER");
  app.add_flag("-p,--password", passwordsw, "Ask for pCloud account password.");
  app.add_option("-t,--tfa_code", tfa_code, "pCloud tfa code");
  app.add_flag("-r,--trusted_device", trusted_device, "Trust this device.");
  app.add_flag("-c,--crypto", crypto, "Ask for crypto password.");
  app.add_flag("-y,--passascrypto", passascrypto_sw, "User password is the same as crypto password.");
  app.add_flag("-d,--daemonize", daemon, "Run the process as a background daemon.");
  app.add_flag("-o,--commands", commands, "Keep parent process alive and process commands.");
  app.add_option("-m,--mountpoint", mountpoint, "Specify where pCloud filesystem is mounted.");
  app.add_flag("-k,--commands_only", commands_only, "Open command prompt to interact with running daemon.");
  app.add_flag("-n,--newuser", newuser, "Register a new pCloud user account.");
  app.add_flag("-s,--savepassword", save_pass, "Save user password in the database.");
  app.add_option("--cache-size", cache_size_gb, "Maximum cache size in GB (default: 5GB).");
  app.add_option("--log-path", log_path, "Custom path for debug.log (default: ~/.pcloud/debug.log).");
  app.add_option("--log-level", log_level, "Logging level: NONE, ERROR, WARNING, INFO (default), NOTICE, DEBUG.");
  app.add_option("--fs-event-log", fs_event_log, "Path to filesystem events log (default: disabled).");
  app.add_option("-O,--fuse-opts", fuse_opts, "FUSE mount options (e.g., 'allow_other,allow_root').");

  app.allow_extras();

  try {
    app.parse(argc, argv);

    if (commands_only) {
      ct::process_commands();
      exit(0);
    }

    bool has_piped_input = !isatty(STDIN_FILENO);
    if (has_piped_input && app.count("-h") == 0 && app.count("--help") == 0) {
      std::string line;
      if (std::getline(std::cin, line) && !line.empty()) {
        return ct::process_command(line);
      }
    }

    if (username.empty()) {
      std::cout << "Username option is required, specify with "
                << "-u or --username, or set PCLOUD_USER." << std::endl;
      return 1;
    }

    for (int i = 1; i < argc; ++i) {
      memset(argv[i], 0, strlen(argv[i]));
    }
    if (daemon) {
      strncpy(argv[0], "pCloudDriveDaemon", strlen(argv[0]));
    } else {
      strncpy(argv[0], "pCloudDrive", strlen(argv[0]));
    }

    cc::clibrary::pclsync_lib::get_lib().set_username(username);
    if (passwordsw) {
      cc::clibrary::pclsync_lib::get_lib().read_password();
    } else {
      const char *env_pass = std::getenv("PCLOUD_ACCOUNT_PASSWORD");
      if (env_pass && env_pass[0]) {
        cc::clibrary::pclsync_lib::get_lib().set_password(std::string(env_pass));
      }
    }
    cc::clibrary::pclsync_lib::get_lib().set_tfa_code(tfa_code);
    cc::clibrary::pclsync_lib::get_lib().set_trusted_device(trusted_device);
    if (crypto) {
      cc::clibrary::pclsync_lib::get_lib().setup_crypto_ = true;
      if (passascrypto_sw) {
        cc::clibrary::pclsync_lib::get_lib().set_crypto_pass(cc::clibrary::pclsync_lib::get_lib().get_password());
      } else {
        const char *env_crypto = std::getenv("PCLOUD_CRYPTO_PASSWORD");
        if (env_crypto && env_crypto[0]) {
          cc::clibrary::pclsync_lib::get_lib().set_crypto_pass(std::string(env_crypto));
        } else {
          std::cout << "Enter crypto password." << std::endl;
          cc::clibrary::pclsync_lib::get_lib().read_cryptopass();
        }
      }
    } else
      cc::clibrary::pclsync_lib::get_lib().setup_crypto_ = false;

    if (app.count("--mountpoint") > 0 || app.count("-m") > 0) {
      cc::clibrary::pclsync_lib::get_lib().set_mount(mountpoint);
    }

    if (app.count("--cache-size") > 0) {
      /* Validate cache size: minimum 1GB, maximum 1TB */
      if (cache_size_gb < 1 || cache_size_gb > 1024) {
        std::cerr << "error: cache-size must be between 1 and 1024 GB" << std::endl;
        return 1;
      }
      uint64_t cache_size_bytes = cache_size_gb * 1024ULL * 1024ULL * 1024ULL;
      char cache_size_str[32];
      snprintf(cache_size_str, sizeof(cache_size_str), "%llu",
               (unsigned long long)cache_size_bytes);
      setenv("PCLOUD_CACHE_SIZE", cache_size_str, 1);
    }

    if (app.count("--log-path") > 0) {
      /* Validate log path: must not be empty or start with /etc or /sys */
      if (log_path.empty() || log_path.compare(0, 5, "/etc/") == 0 || log_path.compare(0, 5, "/sys/") == 0) {
        std::cerr << "error: invalid log-path" << std::endl;
        return 1;
      }
      setenv("PCLOUD_LOG_PATH", log_path.c_str(), 1);
    }

    if (app.count("--log-level") > 0) {
      setenv("PCLOUD_LOG_LEVEL", log_level.c_str(), 1);
    } else {
      /* Set default log level to INFO */
      setenv("PCLOUD_LOG_LEVEL", "INFO", 1);
    }

    if (app.count("--fs-event-log") > 0) {
      /* Validate fs-event-log path: must not be empty or start with /etc or /sys */
      if (fs_event_log.empty() || fs_event_log.compare(0, 5, "/etc/") == 0 || fs_event_log.compare(0, 5, "/sys/") == 0) {
        std::cerr << "error: invalid fs-event-log" << std::endl;
        return 1;
      }
      setenv("PCLOUD_FS_EVENT_LOG", fs_event_log.c_str(), 1);
    }

    if (app.count("--fuse-opts") > 0 || app.count("-O") > 0) {
      setenv("PCLOUD_FUSE_OPTS", fuse_opts.c_str(), 1);
    }

    cc::clibrary::pclsync_lib::get_lib().newuser_ = newuser;
    cc::clibrary::pclsync_lib::get_lib().set_savepass(save_pass);
    cc::clibrary::pclsync_lib::get_lib().set_daemon(daemon);
  } catch (const CLI::ParseError &e) {
    return app.exit(e);
  } catch (const std::exception &e) {
    std::cerr << "error: " << e.what() << std::endl;
    return 1;
  } catch (...) {
    std::cerr << "Exception of unknown type!" << std::endl;
    return 1;
  }

  if (daemon) {
    ct::daemonize(commands);
  } else {
    if (commands) {
      std::cout << "Option commands /o ignored." << std::endl;
    }
    if (!cc::clibrary::pclsync_lib::get_lib().init()) {
      sleep(360000);
    }
  }

  if (!tfa_code.empty()) {
    putil_wipe(&tfa_code[0], tfa_code.size());
  }

  cc::clibrary::pclsync_lib::get_lib().wipe_password();
  cc::clibrary::pclsync_lib::get_lib().wipe_crypto_pass();
  cc::clibrary::pclsync_lib::get_lib().wipe_tfa_code();

  return 0;
}
