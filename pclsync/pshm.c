#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdbool.h>
#include <errno.h>

#include "pdbg.h"
#include "pshm.h"
#include "ppath.h"

static key_t get_key() {
    char path[PATH_MAX];
    char *home;
    
    home = ppath_home();
    if(!home) {
        pdbg_logf(D_ERROR, "HOME environment variable is not set");
        return (key_t)-1;
    }
    snprintf(path, sizeof(path), "%s/.pcloud/data.db", home);
    free(home);
    return ftok(path, 'A');
}

static int get_id() {
	key_t key;

	key = get_key();
	if(key == -1) {
		pdbg_logf(D_ERROR, "failed to get ipc key");
		return -1;
	}

	return shmget(key, PSYNC_SHM_SIZE, IPC_CREAT | 0666);
}

bool pshm_read(void **data, size_t *datasz) {
    int shmid;
    psync_shm *shm;
    int flag;
    char *dataArea;

    shmid = get_id();
    if (shmid == -1) {
        pdbg_logf(D_ERROR, "Failed to get shared memory ID");
        return false;
    }

    shm = (psync_shm*)shmat(shmid, NULL, 0);
    if (shm == (void*)-1) {
        pdbg_logf(D_ERROR, "Failed to attach to shared memory: %s", strerror(errno));
        return false;
    }

    __atomic_load(&shm->flag, &flag, __ATOMIC_SEQ_CST);
    if(flag != 1) {
        shmdt(shm);
        return false;
    }

    if(datasz != NULL) {
        *datasz = shm->datasz;
    }

    *data = malloc(shm->datasz);
    if(*data == NULL) {
        pdbg_logf(D_ERROR, "Failed to allocate memory for shared data");
        shmdt(shm);
        return false;
    }

    dataArea = (char *)shm + sizeof(psync_shm);
    memcpy(*data, dataArea, shm->datasz);
    
    __atomic_store_n(&shm->flag, 0, __ATOMIC_SEQ_CST);

    shmdt(shm);
    return true;
}

void pshm_write(const void *data, size_t datasz) {
    int shmid;
    psync_shm* shm;
    char *dataArea;
    
    if (datasz > PSYNC_SHM_SIZE - sizeof(psync_shm)) {
        pdbg_logf(D_ERROR, "Data size exceeds available shared memory size");
        return;
    }

    shmid = get_id();
    if (shmid == -1) {
        pdbg_logf(D_ERROR, "Failed to get shared memory ID");
        return;
    }

    shm = (psync_shm*)shmat(shmid, NULL, 0);
    if (shm == (void*)-1) {
        pdbg_logf(D_ERROR, "Failed to attach to shared memory: %s", strerror(errno));
        return;
    }

    if (shm->flag == 0 && shm->datasz == 0) {
        pdbg_logf(D_NOTICE, "Initializing shared memory segment");
        // Clear the structure first
        memset(shm, 0, sizeof(psync_shm));
        // Data area starts right after the structure
        shm->data = (char *)shm + sizeof(psync_shm);
        shm->datasz = 0;
        shm->flag = 0;
    }

    dataArea = (char *)shm + sizeof(psync_shm);
    memcpy(dataArea, data, datasz);

    shm->datasz = datasz;
    __atomic_store_n(&shm->flag, 1, __ATOMIC_SEQ_CST);
    
    if (shmdt(shm) == -1) {
        pdbg_logf(D_ERROR, "Failed to detach from shared memory: %s", strerror(errno));
    }
}

int pshm_cleanup() {
	return shmctl(get_id(), IPC_RMID, NULL);
}