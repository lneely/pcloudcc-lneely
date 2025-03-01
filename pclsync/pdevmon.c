/*
   Copyright (c) 2013-2014 Anton Titov.

   Copyright (c) 2013-2014 pCloud Ltd.  All rights reserved.

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
#include <libudev.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "plibs.h"
#include "psynclib.h"
#include "prun.h"


#include "pdevmon.h"
#include "plocalscan.h"
#include "ptimer.h"

#define DEV_MONITOR_ACTIVITY_TIMER_INT 20

static pthread_mutex_t devmon_mutex = PTHREAD_MUTEX_INITIALIZER;
static psync_timer_t devmon_activity_timer = NULL;

static void on_timer_activity() {
  psync_timer_stop(devmon_activity_timer);
  pthread_mutex_lock(&devmon_mutex);
  devmon_activity_timer = NULL;
  pthread_mutex_unlock(&devmon_mutex);
  psync_restat_sync_folders();
}

static void timer_start() {
  pthread_mutex_lock(&devmon_mutex);
  if (!devmon_activity_timer)
    devmon_activity_timer = psync_timer_register(on_timer_activity, DEV_MONITOR_ACTIVITY_TIMER_INT, NULL);
  pthread_mutex_unlock(&devmon_mutex);
}

static void enum_devices(struct udev *udev, device_event event) {
  timer_start();
}

static void monitor_usb() {
  struct udev *udev;
  struct udev_device *dev;
  struct udev_monitor *mon;
  int fd;

  udev = udev_new();
  if (!udev) {
    debug(D_WARNING, "Can't create udev\n");
    return;
  }
  mon = udev_monitor_new_from_netlink(udev, "udev");
  udev_monitor_filter_add_match_subsystem_devtype(mon, "usb", NULL);
  udev_monitor_enable_receiving(mon);
  /* Get the file descriptor (fd) for the monitor.
     This fd will get passed to select() */
  fd = udev_monitor_get_fd(mon);
  while (1) {
    /* Set up the call to select(). In this case, select() will
       only operate on a single file descriptor, the one
       associated with our udev_monitor. Note that the timeval
       object is set to 0, which will cause select() to not
       block. */
    fd_set fds;
    struct timeval tv;
    int ret;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    ret = select(fd + 1, &fds, NULL, NULL, &tv);
    /* Check if our file descriptor has received data. */
    if (ret > 0 && FD_ISSET(fd, &fds)) {

      /* Make the call to receive the device.
         select() ensured that this will not block. */
      dev = udev_monitor_receive_device(mon);
      if (dev) {
        enum_devices(udev, Dev_Event_arrival);
      } else {
        // printf("No Device from receive_device(). An error occured.\n");
      }
    }
    usleep(250 * 1000);
    fflush(stdout);
  }
  udev_unref(udev);
  return;
}

static void proc_devmon() {
  debug(D_NOTICE, "Waiting for USB devices connect/disconnect events");
  monitor_usb();
}

void pdevmon_init() {
  prun_thread("libusb handle events completed thread", proc_devmon);
}
