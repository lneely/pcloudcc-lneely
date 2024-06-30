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

#include "plibs.h"
#include "psynclib.h"
// #include "pdevice_monitor.h"
#include "papi.h"
#include "pbusinessaccount.h"
#include "pdevicemap.h"
#include "pnetlibs.h"

#include "pdevice_monitor.h"
// #include "pdevicemap.h"
#include "plocalscan.h"
#include "ptimer.h"

#define DEV_MONITOR_ACTIVITY_TIMER_INT 20

static pthread_mutex_t devmon_mutex = PTHREAD_MUTEX_INITIALIZER;
static psync_timer_t devmon_activity_timer = NULL;

void devmon_activity_timer_action() {
  psync_timer_stop(devmon_activity_timer);
  pthread_mutex_lock(&devmon_mutex);
  devmon_activity_timer = NULL;
  pthread_mutex_unlock(&devmon_mutex);
  psync_restat_sync_folders();
}

void devmon_activity_timer_start() {
  pthread_mutex_lock(&devmon_mutex);
  if (!devmon_activity_timer)
    devmon_activity_timer = psync_timer_register(
        devmon_activity_timer_action, DEV_MONITOR_ACTIVITY_TIMER_INT, NULL);
  pthread_mutex_unlock(&devmon_mutex);
}

// device_event_callback *device_callbacks;
// int device_clbsize = 10;
// int device_clbnum = 0;

// void psync_add_device_monitor_callback(device_event_callback callback) {
//   if (callback) {
//     if (device_clbnum == 0)
//       device_callbacks = (device_event_callback
//       *)psync_malloc(sizeof(device_event_callback)*device_clbsize);
//     else {
//       while (device_clbnum > device_clbsize) {
//         device_event_callback *callbacks_old = device_callbacks;
//         device_callbacks = (device_event_callback
//         *)psync_malloc(sizeof(device_event_callback)*device_clbsize*2);
//         memccpy(device_callbacks, callbacks_old,
//         0,sizeof(device_event_callback)*device_clbsize); device_clbsize =
//         device_clbsize * 2; psync_free(callbacks_old);
//       }
//     }
//     device_callbacks[device_clbnum] = callback;
//     device_clbnum
//     ++;
//   }
// }

// static pdevice_info * new_dev_info( char *szPath, pdevice_types type,
// device_event evt) {
//   /*int pathsize = strlen(szPath);
//   int infstrsize = sizeof(pdevice_info);
//   int infsize = pathsize + infstrsize + 1;*/
//  // pdevice_info *infop = (pdevice_info *)psync_malloc(infsize);
//   pdevice_info *infop = (pdevice_info *)psync_malloc(sizeof(pdevice_info));
//   //ZeroMemory(infop, infsize);
//   //infop->filesystem_path = (char *)(infop) + infstrsize;
//   infop->filesystem_path = strdup(szPath);
//   //memcpy(infop->filesystem_path, szPath, pathsize);
//   //infop->filesystem_path[pathsize] = '\0';
//   infop->type = type;
//   infop->isextended = 0;
//   return infop;
// }

// static pdevice_extended_info * new_dev_ext_info(char *szPath, char * vendor,
// char *product, char* deviceid, pdevice_types type, device_event evt) {
//  /*uint32_t pathsize = strlen(szPath);
//   uint32_t vndsize = strlen(vendor);
//   uint32_t prdsize = strlen(product);
//   uint32_t devsize = strlen(deviceid);
//   uint32_t infstrsize = sizeof(pdevice_extended_info);
//   uint32_t infsize = pathsize + infstrsize + pathsize + vndsize + prdsize +
//   5; void * infovp = psync_malloc(infsize); pdevice_extended_info *infop =
//   (pdevice_extended_info *)infovp; ZeroMemory(infop, infsize); char
//   *storage_begin = (char *)(infovp)+infstrsize;
//   put_into_storage(&infop->filesystem_path, &storage_begin, szPath,
//   pathsize); put_into_storage(&infop->vendor, &storage_begin, vendor,
//   vndsize); put_into_storage(&infop->product, &storage_begin, product,
//   prdsize); put_into_storage(&infop->device_id, &storage_begin, deviceid,
//   devsize); infop->type = type; infop->event = evt; infop->isextended = 1;
//   infop->size = infsize;
//   infop->me = infop;*/
//   pdevice_extended_info *infop = (pdevice_extended_info
//   *)psync_malloc(sizeof(pdevice_extended_info)); infop->filesystem_path =
//   strdup(szPath); infop->vendor = strdup(vendor); infop->product =
//   strdup(product); infop->device_id = strdup(deviceid); infop->type = type;
//   infop->isextended = 1;
//   return infop;
// }

// void psync_devmon_notify_device_callbacks(pdevice_extended_info * param,
// device_event event) {
//   if (event == Dev_Event_arrival)
//     psync_run_thread1("Device notifications", do_notify_device_callbacks_in,
//     (void*)param);
//   else
//     psync_run_thread1("Device notifications", do_notify_device_callbacks_out,
//     (void*)param);
// }

// static void psync_devmon_arivalmonitor(device_event event, void *
// device_info)
//{
//   pdevice_extended_info *pDevExtInfo = (pdevice_extended_info*)device_info;
//   if (event == Dev_Event_arrival){
//	debug(D_NOTICE, "Device arrived.");
//	psync_do_restat_sync_folders();
//   }
//   else{
//	debug(D_NOTICE, "Device removed.");
//	psync_do_restat_sync_folders();
//   }
//   if (pDevExtInfo)
//	print_device_info(pDevExtInfo);
// }

#include <libudev.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void enumerate_devices(struct udev *udev, device_event event) {
  devmon_activity_timer_start();
}

void monitor_usb_dev() {
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
        enumerate_devices(udev, Dev_Event_arrival);
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

void device_monitor_thread() {
  debug(D_NOTICE, "Waiting for USB devices connect/disconnect events");
  monitor_usb_dev();
}

void psync_devmon_init() {
  psync_run_thread("libusb handle events completed thread",
                   device_monitor_thread);
}
