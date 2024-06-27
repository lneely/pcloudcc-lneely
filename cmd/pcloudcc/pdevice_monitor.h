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

#pragma once

#ifndef _PDEVICE_MONITOR
#define _PDEVICE_MONITOR
#include <stdint.h>
typedef enum {
  Dev_Types_UsbRemovableDisk = 1,
  Dev_Types_UsbFixedDisk,
  Dev_Types_CDRomMedia,
  Dev_Types_CameraDevice,
  Dev_Types_AndroidDevice
} pdevice_types;

typedef enum {
  Dev_Event_arrival = 1,
  Dev_Event_removed
} device_event;

typedef struct _pdevice_info pdevice_info;
struct _pdevice_info {
  pdevice_types type;
  device_event event;
  int size;
  int isextended;
  char * filesystem_path;
  pdevice_info *me;
};

typedef struct _pdevice_extended_info pdevice_extended_info;
struct _pdevice_extended_info {
  pdevice_types type;
  device_event event;
  int size;
  int isextended;
  char *filesystem_path;
  char *vendor;
  char *product;
  char *device_id;
  pdevice_extended_info * me;
};

typedef void(*device_event_callback)(void * device_info_);

#ifdef __cplusplus
extern "C" {
#endif

  void padd_monitor_callback(device_event_callback callback);
  void pinit_device_monitor();

#ifdef __cplusplus
}
#endif

#endif //_PDEVICE_MONITOR
