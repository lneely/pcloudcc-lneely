#ifndef __PDEVICE_H
#define __PDEVICE_H

#ifdef __cplusplus
extern "C" {
#endif

#define pdevice_id_short(deviceid) (deviceid)

char *pdevice_id();
char *pdevice_name();

char *pdevice_get_os();

const char *pdevice_get_software();
void pdevice_set_software(const char *snm);

#ifdef __cplusplus
}
#endif

#endif