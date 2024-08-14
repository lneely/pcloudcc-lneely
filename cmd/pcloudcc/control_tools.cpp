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

#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include "control_tools.h"
#include "overlay_client.h"
#include "pclsync_lib_c.h"

#include "pclsync_lib.h"

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

int start_crypto(const char *pass) {
  int ret;
  char *errm;
  size_t errm_size;

  int result = SendCall(STARTCRYPTO, pass, &ret, &errm, &errm_size);
  if (result != 0 || ret != 0) {
    std::cout << "Start Crypto failed. return is " << ret << " and message is "
              << errm << std::endl;
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
  if (result != 0 || ret != 0) {
    std::cout << "Stop Crypto failed. return is " << ret << " and message is "
              << errm << std::endl;
  } else {
    std::cout << "Crypto Stopped. " << std::endl;
  }

  if (errm)
    free(errm);
  return ret;
}

int finalize() {
  int ret;
  char *errm;
  size_t errm_size;

  int result = SendCall(FINALIZE, "", &ret, &errm, &errm_size);
  if (result != 0 || ret != 0) {
    std::cout << "Finalize failed. return code is " << result << ", ret is "
              << ret << ", and message is " << (errm ? errm : "no message")
              << std::endl;
  } else {
    std::cout << "Exiting ..." << std::endl;
  }

  if (errm)
    free(errm);

  return ret;
}

void process_commands() {
  std::cout << "Supported commands are:" << std::endl
            << "startcrypto <crypto pass>, "
            << "stopcrypto, "
            << "finalize, "
            << "q, quit" << std::endl;
  std::cout << "> ";

  for (std::string line; std::getline(std::cin, line);) {
    if (!line.compare("finalize")) {
      finalize();
      break;
    } else if (!line.compare("stopcrypto")) {
      stop_crypto();
    } else if (!line.compare(0, 11, "startcrypto", 0, 11) &&
               (line.length() > 12)) {
      start_crypto(line.c_str() + 12);
    } else if (!line.compare("q") || !line.compare("quit")) {
      break;
    }
    std::cout << "> ";
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
