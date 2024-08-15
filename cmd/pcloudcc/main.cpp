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
#include "pclsync_lib_c.h"

#include "pclsync_lib.h"

namespace po = boost::program_options;
namespace ct = control_tools;
namespace cc = console_client;

// TODO: a proper version string might be useful for debugging
static std::string version = "git";

int main(int argc, char **argv) {
  std::cout << "pCloud console client v." << version << std::endl;
  std::string username;
  std::string password;
  bool daemon = false;
  bool commands = false;
  bool commands_only = false;
  bool newuser = false;
  bool passwordsw = false;
  bool save_pass = false;
  bool crypto = false;
  po::variables_map vm;

  try {
    po::options_description desc("Allowed options");
    desc.add_options()("help,h", "Show this help message.")(
        "username,u", po::value<std::string>(&username),
        "pCloud account name.")("password,p", po::bool_switch(&passwordsw),
                                "Ask for pCloud account password.")(
        "crypto,c", po::bool_switch(&crypto), "Ask for crypto password.")(
        "passascrypto,y", po::value<std::string>(),
        "User password is the same as crypto password.")(
        "daemonize,d", po::bool_switch(&daemon),
        "Run the process as a background daemon.")(
        "commands ,o", po::bool_switch(&commands),
        "Keep parent process alive and process commands. ")(
        "mountpoint,m", po::value<std::string>(),
        "Specify where pCloud filesystem is mounted.")(
        "commands_only,k", po::bool_switch(&commands_only),
        "Open command prompt to interact with running daemon.")(
        "newuser,n", po::bool_switch(&newuser),
        "Register a new pCloud user account.")(
        "savepassword,s", po::bool_switch(&save_pass),
        "Save user password in the database.");
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if (vm.count("help")) {
      std::cout << desc << "\n";
      return 0;
    }

    if (commands_only) {
      ct::process_commands();
      exit(0);
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
      cc::clibrary::pclsync_lib::get_lib().get_pass_from_console();
    }
    if (crypto) {
      cc::clibrary::pclsync_lib::get_lib().setup_crypto_ = true;
      if (vm.count("passascrypto")) {
        cc::clibrary::pclsync_lib::get_lib().set_crypto_pass(password);
      } else {
        std::cout << "Enter crypto password." << std::endl;
        cc::clibrary::pclsync_lib::get_lib().get_cryptopass_from_console();
      }
    } else
      cc::clibrary::pclsync_lib::get_lib().setup_crypto_ = false;

    if (vm.count("mountpoint")) {
      cc::clibrary::pclsync_lib::get_lib().set_mount(
          vm["mountpoint"].as<std::string>());
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
