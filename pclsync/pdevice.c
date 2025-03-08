/*
   Copyright (c) 2013 Anton Titov.

   Copyright (c) 2013 pCloud Ltd.  All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met: Redistributions of source code must retain the above
   copyright notice, this list of conditions and the following
   disclaimer.  Redistributions in binary form must reproduce the
   above copyright notice, this list of conditions and the following
   disclaimer in the documentation and/or other materials provided
   with the distribution.  Neither the name of pCloud Ltd nor the
   names of its contributors may be used to endorse or promote
   products derived from this software without specific prior written
   permission.

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

#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include "pdevice.h"
#include "plibs.h"
#include "psettings.h"
#include "psynclib.h"

static const char *psync_os_name = NULL;
static const char *psync_software_name = PSYNC_LIB_VERSION;

char *pdevice_id() {
  const char *hardware;
  char *device, *path;
  char buf[8];
  DIR *dh;
  struct dirent *de;
  int fd;

  hardware = "Desktop";
  dh = opendir("/sys/class/power_supply");
  if (dh) {
    while ((de = readdir(dh))) {
      if (de->d_name[0] != '.' ||
          (de->d_name[1] != 0 &&
           (de->d_name[1] != '.' || de->d_name[2] != 0))) {
        path =
            psync_strcat("/sys/class/power_supply/", de->d_name, "/type", NULL);
        fd = open(path, O_RDONLY);
        psync_free(path);
        if (fd == -1)
          continue;
        if (read(fd, buf, 7) == 7 && !memcmp(buf, "Battery", 7)) {
          close(fd);
          hardware = "Laptop";
          break;
        }
        close(fd);
      }
    }
    closedir(dh);
  }
  device = psync_strcat(hardware, ", Linux", NULL);
  return device;
}

char *pdevice_name() {
  char *osname = pdevice_get_os();
  char *ret = psync_strcat(osname, ", ", psync_software_name, NULL);
  free(osname);
  return ret;
}

char *pdevice_get_os() {
  return psync_os_name ? psync_strdup(psync_os_name) : pdevice_id();
}

void pdevice_set_software(const char *snm) { 
  psync_software_name = snm; 
}

const char *pdevice_get_software() { 
  return psync_software_name; 
}
