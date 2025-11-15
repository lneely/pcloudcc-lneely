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
#include <iostream>
#include <string>

#include <boost/program_options.hpp>

#include "control_tools.h"

#include "pclsync_lib.h"
#include "pclsync/psettings.h"

namespace po = boost::program_options;
namespace ct = control_tools;
namespace cc = console_client;

// TODO: a proper version string might be useful for debugging
static std::string version = "git-lneely";

int main(int argc, char **argv) {
  std::cout << "pCloud console client (" << version << ")" << std::endl;
  std::string username = "";
  std::string password = "";
  std::string tfa_code = "";
  bool daemon = false;
  bool commands = false;
  bool commands_only = false;
  bool newuser = false;
  bool passwordsw = false;
  bool save_pass = false;
  bool crypto = false;
  bool trusted_device = false;
  po::variables_map vm;

  try {
    po::options_description desc("Allowed options");
    desc.add_options()
    ("help,h", "Show this help message.")
    ("username,u", po::value<std::string>(&username), "pCloud account name.")
    ("password,p", po::bool_switch(&passwordsw), "Ask for pCloud account password.")
    ("tfa_code,t", po::value<std::string>(&tfa_code), "pCloud tfa code")
    ("trusted_device,r", po::bool_switch(&trusted_device), "Trust this device.")
    ("crypto,c", po::bool_switch(&crypto), "Ask for crypto password.")
    ("passascrypto,y", po::value<std::string>(), "User password is the same as crypto password.")
    ("daemonize,d", po::bool_switch(&daemon), "Run the process as a background daemon.")
    ("commands ,o", po::bool_switch(&commands), "Keep parent process alive and process commands. ")
    ("mountpoint,m", po::value<std::string>(), "Specify where pCloud filesystem is mounted.")
    ("commands_only,k", po::bool_switch(&commands_only), "Open command prompt to interact with running daemon.")
    ("newuser,n", po::bool_switch(&newuser), "Register a new pCloud user account.")
    ("savepassword,s", po::bool_switch(&save_pass), "Save user password in the database.")
    ("cache-size", po::value<uint64_t>(), "Maximum cache size in GB (default: 5GB).")
    ("log-path", po::value<std::string>(), "Custom path for debug.log (default: ~/.pcloud/debug.log).")
    ("log-level", po::value<std::string>(), "Logging level: NONE, ERROR, WARNING, INFO (default), NOTICE, DEBUG.")
    ("fs-event-log", po::value<std::string>(), "Path to filesystem events log (default: disabled).");

    po::command_line_parser parser{argc, argv};
    po::positional_options_description p;
    parser.options(desc).positional(p).allow_unregistered();
    po::parsed_options parsed_options = parser.run();
    po::store(parsed_options, vm);

    po::notify(vm);

    if (vm.count("help")) {
      std::cout << desc << "\n";
      return 0;
    }

    if (commands_only) {
      ct::process_commands();
      exit(0);
    }

    bool has_piped_input = !isatty(STDIN_FILENO);
    if (has_piped_input && !vm.count("help")) {
      std::string line;
      if (std::getline(std::cin, line) && !line.empty()) {
        return ct::process_command(line);
      }
    }


    if ((!vm.count("username"))) {
      std::cout << "Username option is required, specify with "
                << "-u or --username." << std::endl;
      return 1;
    }

    for (int i = 1; i < argc; ++i) {
      memset(argv[i], 0, strlen(argv[i]));
    }
    if (daemon) {
      strncpy(argv[0], "pCloudDriveDeamon", strlen(argv[0]));
    } else {
      strncpy(argv[0], "pCloudDrive", strlen(argv[0]));
    }

    cc::clibrary::pclsync_lib::get_lib().set_username(username);
    if (passwordsw) {
      cc::clibrary::pclsync_lib::get_lib().read_password();
    }
    cc::clibrary::pclsync_lib::get_lib().set_tfa_code(tfa_code);
    cc::clibrary::pclsync_lib::get_lib().set_trusted_device(trusted_device);
    if (crypto) {
      cc::clibrary::pclsync_lib::get_lib().setup_crypto_ = true;
      if (vm.count("passascrypto")) {
        cc::clibrary::pclsync_lib::get_lib().set_crypto_pass(password);
      } else {
        std::cout << "Enter crypto password." << std::endl;
        cc::clibrary::pclsync_lib::get_lib().read_cryptopass();
      }
    } else
      cc::clibrary::pclsync_lib::get_lib().setup_crypto_ = false;

    if (vm.count("mountpoint")) {
      cc::clibrary::pclsync_lib::get_lib().set_mount(
          vm["mountpoint"].as<std::string>());
    }

    if (vm.count("cache-size")) {
      uint64_t cache_size_gb = vm["cache-size"].as<uint64_t>();
      uint64_t cache_size_bytes = cache_size_gb * 1024ULL * 1024ULL * 1024ULL;
      char cache_size_str[32];
      snprintf(cache_size_str, sizeof(cache_size_str), "%llu",
               (unsigned long long)cache_size_bytes);
      setenv("PCLOUD_CACHE_SIZE", cache_size_str, 1);
    }

    if (vm.count("log-path")) {
      setenv("PCLOUD_LOG_PATH", vm["log-path"].as<std::string>().c_str(), 1);
    }

    if (vm.count("log-level")) {
      setenv("PCLOUD_LOG_LEVEL", vm["log-level"].as<std::string>().c_str(), 1);
    } else {
      /* Set default log level to INFO */
      setenv("PCLOUD_LOG_LEVEL", "INFO", 1);
    }

    if (vm.count("fs-event-log")) {
      setenv("PCLOUD_FS_EVENT_LOG", vm["fs-event-log"].as<std::string>().c_str(), 1);
    }

    cc::clibrary::pclsync_lib::get_lib().newuser_ = newuser;
    cc::clibrary::pclsync_lib::get_lib().set_savepass(save_pass);
    cc::clibrary::pclsync_lib::get_lib().set_daemon(daemon);
  } catch (std::exception &e) {
    std::cerr << "error: " << e.what() << std::endl;
    return 1;
  } catch (...) {
    std::cerr << "Exception of unknown type!" << std::endl;
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

  return 0;
}
