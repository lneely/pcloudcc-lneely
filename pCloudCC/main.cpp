#include "control_tools.h"
#include "pclsync_lib.h"
#include <boost/program_options.hpp>
#include <iostream>

namespace po = boost::program_options;
namespace ct = control_tools;
namespace cc = console_client;
static std::string version = "2.0.1";

int
main(int argc, char **argv) {
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
    desc.add_options()
	  ("help,h",
	   "Show this help message.")
	  ("username,u", po::value<std::string>(&username),
	   "pCloud account name.")
	  ("password,p", po::bool_switch(&passwordsw),
	   "Ask for pCloud account password.")
	  ("crypto,c", po::bool_switch(&crypto),
	   "Ask for crypto password.")
	  ("passascrypto,y", po::value<std::string>(),								 "User password is the same as crypto password.")
	  ("daemonize,d", po::bool_switch(&daemon),
	   "Run the process as a background daemon.")
	  ("commands ,o", po::bool_switch(&commands),
	   "Keep parent process alive and process commands. ")
	  ("mountpoint,m", po::value<std::string>(),
	   "Specify where pCloud filesystem is mounted.")
	  ("commands_only,k", po::bool_switch(&commands_only),
	   "Open command prompt to interact with running daemon.")
	  ("newuser,n", po::bool_switch(&newuser),
	   "Register a new pCloud user account.")
	  ("savepassword,s", po::bool_switch(&save_pass),
	   "Save user password in the database.");
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if (vm.count("help")) {
      std::cout << desc << "\n";
      return 0;
    }

    if ((!vm.count("username"))) {
      std::cout << "Username option is required, specify with " <<
		"-u or --username." << std::endl;
      return 1;
    }

    if (commands_only) {
      ct::process_commands();
      exit(0);
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
        cc::clibrary::pclsync_lib::get_lib()
		  .set_crypto_pass(password);
	  } else {
        std::cout << "Enter crypto password." << std::endl;
        cc::clibrary::pclsync_lib::get_lib()
		  .get_cryptopass_from_console();
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
