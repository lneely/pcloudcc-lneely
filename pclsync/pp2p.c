/*
   Copyright (c) 2014 Anton Titov.

   Copyright (c) 2014 pCloud Ltd.  All rights reserved.

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

#include <errno.h>
#include <pthread.h>

#include "papi.h"
#include "pfile.h"
#include "pcrypto.h"
#include "pdownload.h"
#include "pfoldersync.h"
#include "plibs.h"
#include "pnetlibs.h"
#include "pp2p.h"
#include "prun.h"
#include "psettings.h"
#include "pssl.h"
#include "pstatus.h"
#include "psys.h"
#include "ptimer.h"
#include "putil.h"
#include <string.h>

#define P2P_ENCTYPE_RSA_AES 0

typedef uint32_t packet_type_t;
typedef uint32_t packet_id_t;
typedef uint32_t packet_resp_t;

typedef PSYNC_PACKED_STRUCT {
  packet_type_t type;
  unsigned char hashstart[4];
  uint64_t filesize;
  unsigned char rand[PSYNC_HASH_BLOCK_SIZE - PSYNC_HASH_DIGEST_HEXLEN];
  unsigned char genhash[PSYNC_HASH_DIGEST_HEXLEN];
  unsigned char computername[PSYNC_HASH_DIGEST_HEXLEN];
}
packet_check;

typedef PSYNC_PACKED_STRUCT {
  packet_resp_t type;
  uint32_t port;
  unsigned char rand[PSYNC_HASH_BLOCK_SIZE - PSYNC_HASH_DIGEST_HEXLEN];
  unsigned char genhash[PSYNC_HASH_DIGEST_HEXLEN];
}
packet_check_resp;

typedef PSYNC_PACKED_STRUCT {
  packet_type_t type;
  unsigned char hashstart[4];
  uint64_t filesize;
  uint32_t keylen;
  uint32_t tokenlen;
  unsigned char rand[PSYNC_HASH_BLOCK_SIZE - PSYNC_HASH_DIGEST_HEXLEN];
  unsigned char genhash[PSYNC_HASH_DIGEST_HEXLEN];
  unsigned char computername[PSYNC_HASH_DIGEST_HEXLEN];
}
packet_get;

static const int on = 1;

static const size_t min_packet_size[] = {
#define P2P_WAKE 0
    sizeof(packet_type_t),
#define P2P_CHECK 1
    sizeof(packet_check),
#define P2P_GET 2
    sizeof(packet_get)};

#define P2P_RESP_NOPE 0
#define P2P_RESP_HAVEIT 1
#define P2P_RESP_WAIT 2

static pthread_mutex_t p2pmutex = PTHREAD_MUTEX_INITIALIZER;

static int udpsock;
static int files_serving = 0;
static int running = 0;
static int tcpport;

static char computername[PSYNC_HASH_DIGEST_HEXLEN];

static const uint32_t requiredstatuses[] = {
    PSTATUS_COMBINE(PSTATUS_TYPE_AUTH, PSTATUS_AUTH_PROVIDED),
    PSTATUS_COMBINE(PSTATUS_TYPE_RUN, PSTATUS_RUN_RUN),
    PSTATUS_COMBINE(PSTATUS_TYPE_ONLINE, PSTATUS_ONLINE_ONLINE)};

static struct sockaddr_storage paddr;
static socklen_t paddrlen;

static psync_rsa_publickey_t pubkey = PSYNC_INVALID_RSA;
static psync_rsa_privatekey_t privkey = PSYNC_INVALID_RSA;
static psync_binary_rsa_key_t pubkeybin = PSYNC_INVALID_BIN_RSA;

PSYNC_PURE static const char *get_addr(void *addr) {
  if (((struct sockaddr_in *)addr)->sin_family == AF_INET)
    return inet_ntoa(((struct sockaddr_in *)addr)->sin_addr);
  else {
    static char buff[80];
    return inet_ntop(AF_INET6, &((struct sockaddr_in6 *)addr)->sin6_addr, buff,
                     sizeof(buff));
  }
}

PSYNC_PURE static const char *get_peer_addr() {
  if (paddr.ss_family == AF_INET)
    return inet_ntoa(((struct sockaddr_in *)&paddr)->sin_addr);
  else {
    static char buff[80];
    return inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&paddr)->sin6_addr,
                     buff, sizeof(buff));
  }
}

static psync_fileid_t has_file(const unsigned char *hashstart,
                                         const unsigned char *genhash,
                                         const unsigned char *rand,
                                         uint64_t filesize,
                                         unsigned char *realhash) {
  psync_sql_res *res;
  psync_variant_row row;
  psync_fileid_t ret;
  unsigned char hashsource[PSYNC_HASH_BLOCK_SIZE],
      hashbin[PSYNC_HASH_DIGEST_LEN], hashhex[PSYNC_HASH_DIGEST_HEXLEN];
  char like[PSYNC_P2P_HEXHASH_BYTES + 1];
  memcpy(like, hashstart, PSYNC_P2P_HEXHASH_BYTES);
  like[PSYNC_P2P_HEXHASH_BYTES] = '%';
  memcpy(hashsource + PSYNC_HASH_DIGEST_HEXLEN, rand,
         PSYNC_HASH_BLOCK_SIZE - PSYNC_HASH_DIGEST_HEXLEN);
  res = psync_sql_query_rdlock(
      "SELECT id, checksum FROM localfile WHERE checksum LIKE ? AND size=?");
  psync_sql_bind_lstring(res, 1, like, PSYNC_P2P_HEXHASH_BYTES + 1);
  psync_sql_bind_uint(res, 2, filesize);
  while ((row = psync_sql_fetch_row(res))) {
    pdbg_assertw(row[1].type == PSYNC_TSTRING &&
            row[1].length == PSYNC_HASH_DIGEST_HEXLEN);
    memcpy(hashsource, row[1].str, PSYNC_HASH_DIGEST_HEXLEN);
    psync_hash(hashsource, PSYNC_HASH_BLOCK_SIZE, hashbin);
    psync_binhex(hashhex, hashbin, PSYNC_HASH_DIGEST_LEN);
    if (!memcmp(hashhex, genhash, PSYNC_HASH_DIGEST_HEXLEN)) {
      if (realhash)
        memcpy(realhash, row[1].str, PSYNC_HASH_DIGEST_HEXLEN);
      ret = psync_get_number(row[0]);
      psync_sql_free_result(res);
      return ret;
    }
  }
  psync_sql_free_result(res);
  return 0;
}

static int is_downloading(const unsigned char *hashstart,
                                    const unsigned char *genhash,
                                    const unsigned char *rand,
                                    uint64_t filesize,
                                    unsigned char *realhash) {
  download_hashes_t *hashes;
  unsigned char hashsource[PSYNC_HASH_BLOCK_SIZE],
      hashbin[PSYNC_HASH_DIGEST_LEN], hashhex[PSYNC_HASH_DIGEST_HEXLEN];
  size_t i;
  hashes = pdownload_get_hashes();
  for (i = 0; i < hashes->hashcnt; i++) {
    if (memcmp(hashstart, hashes->hashes[i], PSYNC_P2P_HEXHASH_BYTES))
      continue;
    memcpy(hashsource, hashes->hashes[i], PSYNC_HASH_DIGEST_HEXLEN);
    memcpy(hashsource + PSYNC_HASH_DIGEST_HEXLEN, rand,
           PSYNC_HASH_BLOCK_SIZE - PSYNC_HASH_DIGEST_HEXLEN);
    psync_hash(hashsource, PSYNC_HASH_BLOCK_SIZE, hashbin);
    psync_binhex(hashhex, hashbin, PSYNC_HASH_DIGEST_LEN);
    if (!memcmp(hashhex, genhash, PSYNC_HASH_DIGEST_HEXLEN)) {
      if (realhash)
        memcpy(realhash, hashsource, PSYNC_HASH_DIGEST_HEXLEN);
      free(hashes);
      return 1;
    }
  }
  free(hashes);
  return 0;
}

static void psync_p2p_check(const packet_check *packet) {
  unsigned char hashhex[PSYNC_HASH_DIGEST_HEXLEN],
      hashsource[PSYNC_HASH_BLOCK_SIZE], hashbin[PSYNC_HASH_DIGEST_LEN];
  packet_check_resp resp;
  if (!memcmp(packet->computername, computername, PSYNC_HASH_DIGEST_HEXLEN))
    return;
  if (has_file(packet->hashstart, packet->genhash, packet->rand,
                         packet->filesize, hashhex))
    resp.type = P2P_RESP_HAVEIT;
  else if (is_downloading(packet->hashstart, packet->genhash,
                                    packet->rand, packet->filesize, hashhex))
    resp.type = P2P_RESP_WAIT;
  else
    return;
  resp.port = tcpport;
  pssl_rand_strong(resp.rand, sizeof(resp.rand));
  memcpy(hashsource, hashhex, PSYNC_HASH_DIGEST_HEXLEN);
  memcpy(hashsource + PSYNC_HASH_DIGEST_HEXLEN, resp.rand, sizeof(resp.rand));
  psync_hash(hashsource, PSYNC_HASH_BLOCK_SIZE, hashbin);
  psync_binhex(resp.genhash, hashbin, PSYNC_HASH_DIGEST_LEN);
  pdbg_logf(D_NOTICE,
        "replying with %u to a check from %s, looking for %." NTO_STR(
            PSYNC_HASH_DIGEST_HEXLEN) "s",
        (unsigned int)resp.type, get_peer_addr(), hashhex);
  if (files_serving)
    psys_sleep_milliseconds(files_serving * 10);
  if (resp.type == P2P_RESP_WAIT)
    psys_sleep_milliseconds(PSYNC_P2P_INITIAL_TIMEOUT / 4);
  if (!sendto(udpsock, (const char *)&resp, sizeof(resp), 0,
              (const struct sockaddr *)&paddr, paddrlen))
    pdbg_logf(D_WARNING, "sendto to %s failed", get_peer_addr());
}

static void psync_p2p_process_packet(const char *packet, size_t plen) {
  packet_type_t type;
  if (unlikely(plen < sizeof(packet_type_t)))
    return;
  type = *((packet_type_t *)packet);
  if (type >= ARRAY_SIZE(min_packet_size) || min_packet_size[type] > plen)
    return;
  pdbg_logf(D_NOTICE, "got %u packet from %s", (unsigned int)type,
        get_peer_addr());
  switch (type) {
  case P2P_WAKE:
    break;
  case P2P_CHECK:
    psync_p2p_check((packet_check *)packet);
    pdbg_logf(D_NOTICE, "processed P2P packed");
    break;
  default:
    pdbg_logf(D_BUG, "handler for packet type %u not implemented", (unsigned)type);
    break;
  }
}

static int socket_write_all(int sock, const void *buff, size_t len) {
  ssize_t ret;
  while (len) {
    ret = write(sock, buff, len);
    if (ret == SOCKET_ERROR) {
      if (errno == EINTR || errno == EAGAIN ||
          errno == EWOULDBLOCK)
        continue;
      return -1;
    }
    buff = (const char *)buff + ret;
    len -= ret;
  }
  return 0;
}

static int socket_read_all(int sock, void *buff, size_t len) {
  ssize_t ret;
  while (len) {
    ret = read(sock, buff, len);
    if (ret == SOCKET_ERROR) {
      if (errno == EINTR || errno == EAGAIN ||
          errno == EWOULDBLOCK)
        continue;
      return -1;
    } else if (ret == 0)
      return -1;
    buff = (char *)buff + ret;
    len -= ret;
  }
  return 0;
}

static int check_token(char *token, uint32_t tlen, unsigned char *key,
                       uint32_t keylen, unsigned char *hashhex) {
  binparam params[] = {
      PAPI_LSTR(PSYNC_CHECKSUM, hashhex, PSYNC_HASH_DIGEST_HEXLEN),
      PAPI_LSTR("keydata", key, keylen), PAPI_LSTR("token", token, tlen)};
  psock_t *api;
  binresult *res;
  uint64_t result;
  api = psync_apipool_get();
  if (pdbg_unlikely(!api))
    return 0;
  res = papi_send2(api, "checkfileownershiptoken", params);
  if (pdbg_unlikely(!res)) {
    psync_apipool_release_bad(api);
    return 0;
  }
  psync_apipool_release(api);
  result = papi_find_result2(res, "result", PARAM_NUM)->num;
  free(res);
  return result ? 0 : 1;
}

static void psync_p2p_tcphandler(void *ptr) {
  packet_get packet;
  psync_fileid_t localfileid;
  psync_binary_rsa_key_t binpubrsa;
  psync_rsa_publickey_t pubrsa;
  psync_symmetric_key_t aeskey;
  psync_encrypted_symmetric_key_t encaeskey;
  pcrypto_ctr_encdec_t encoder;
  char *token, *localpath;
  uint64_t off;
  size_t rd;
  int sock;
  int fd;
  uint32_t keylen, enctype;
  unsigned char hashhex[PSYNC_HASH_DIGEST_HEXLEN], buff[4096];
  sock = *((int *)ptr);
  free(ptr);
  pdbg_logf(D_NOTICE, "got tcp connection");
  if (pdbg_unlikely(socket_read_all(sock, &packet, sizeof(packet))))
    goto err0;
  if (pdbg_unlikely(packet.keylen > PSYNC_P2P_RSA_SIZE) ||
      pdbg_unlikely(packet.tokenlen >
                   512)) /* lets allow 8 times larger keys than we use */
    goto err0;
  localfileid = has_file(packet.hashstart, packet.genhash,
                                   packet.rand, packet.filesize, hashhex);
  if (!localfileid) {
    pdbg_logf(D_WARNING, "got request for file that we do not have");
    goto err0;
  }
  binpubrsa = pssl_alloc_binary_rsa(packet.keylen);
  if (pdbg_unlikely(
          socket_read_all(sock, binpubrsa->data, binpubrsa->datalen))) {
    free(binpubrsa);
    goto err0;
  }
  token = malloc(sizeof(char) * packet.tokenlen);
  if (pdbg_unlikely(socket_read_all(sock, token, packet.tokenlen)) ||
      pdbg_unlikely(!check_token(token, packet.tokenlen, binpubrsa->data,
                                packet.keylen, hashhex))) {
    free(binpubrsa);
    free(token);
    goto err0;
  }
  free(token);
  pubrsa = prsa_binary_to_public(binpubrsa);
  free(binpubrsa);
  if (pdbg_unlikely(pubrsa == PSYNC_INVALID_RSA))
    goto err0;
  localpath = pfolder_lpath_lfile(localfileid, NULL);
  if (pdbg_unlikely(!localpath))
    goto err0;
  fd = pfile_open(localpath, O_RDONLY, 0);
  pdbg_logf(D_NOTICE, "sending file %s to peer", localpath);
  free(localpath);
  if (fd == INVALID_HANDLE_VALUE) {
    pdbg_logf(D_WARNING, "could not open local file %lu",
          (unsigned long)localfileid);
    goto err0;
  }
  aeskey = pcrypto_key();
  encaeskey = psymkey_encrypt(pubrsa, aeskey);
  encoder = pcrypto_ctr_encdec_create(aeskey);
  psymkey_free(aeskey);
  keylen = encaeskey->datalen;
  enctype = P2P_ENCTYPE_RSA_AES;
  if (pdbg_unlikely(encaeskey == PSYNC_INVALID_ENC_SYM_KEY) ||
      pdbg_unlikely(encoder == PSYNC_CRYPTO_INVALID_ENCODER) ||
      pdbg_unlikely(
          socket_write_all(sock, &keylen, sizeof(keylen)) ||
          socket_write_all(sock, &enctype, sizeof(enctype)) ||
          socket_write_all(sock, encaeskey->data, encaeskey->datalen))) {
    if (encaeskey != PSYNC_INVALID_ENC_SYM_KEY)
      free(encaeskey);
    if (encoder != PSYNC_CRYPTO_INVALID_ENCODER)
      pcrypto_ctr_encdec_free(encoder);
    pfile_close(fd);
    goto err0;
  }
  free(encaeskey);
  off = 0;
  while (off < packet.filesize) {
    if (packet.filesize - off < sizeof(buff))
      rd = packet.filesize - off;
    else
      rd = sizeof(buff);
    if (pdbg_unlikely(pfile_read(fd, buff, rd) != rd))
      break;
    pcrypto_ctr_encdec_decode(encoder, buff, rd, off);
    if (pdbg_unlikely(socket_write_all(sock, buff, rd)))
      break;
    off += rd;
  }
  pcrypto_ctr_encdec_free(encoder);
  pfile_close(fd);
  pdbg_logf(D_NOTICE, "file sent successfuly");
err0:
  close(sock);
}

static void psync_p2p_thread() {
  ssize_t ret;
  char buff[2048];
  /*  struct sockaddr_in6 addr; */
  struct sockaddr_in addr4;
  int tcpsock, socks[2], *inconn;
  socklen_t sl;
  int sret;
  pstatus_wait_statuses_arr(requiredstatuses, ARRAY_SIZE(requiredstatuses));
  tcpsock = INVALID_SOCKET;
  /*  udpsock=psock_create(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (pdbg_unlikely(udpsock==INVALID_SOCKET)){*/
  udpsock = psock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (pdbg_unlikely(udpsock == INVALID_SOCKET))
    goto ex;
  setsockopt(udpsock, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on));
  memset(&addr4, 0, sizeof(addr4));
  addr4.sin_family = AF_INET;
  addr4.sin_port = htons(PSYNC_P2P_PORT);
  addr4.sin_addr.s_addr = INADDR_ANY;
  if (pdbg_unlikely(bind(udpsock, (struct sockaddr *)&addr4, sizeof(addr4)) ==
                   SOCKET_ERROR))
    goto ex;
  /*  }
    else{
      setsockopt(udpsock, SOL_SOCKET, SO_REUSEADDR, (const char *)&on,
    sizeof(on)); memset(&addr, 0, sizeof(addr)); addr.sin6_family=AF_INET6;
      addr.sin6_port  =htons(PSYNC_P2P_PORT);
      addr.sin6_addr  =in6addr_any;
      if (pdbg_unlikely(bind(udpsock, (struct sockaddr *)&addr,
    sizeof(addr))==SOCKET_ERROR)) goto ex;
    }
    tcpsock=psock_create(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (pdbg_unlikely(tcpsock==INVALID_SOCKET)){*/
  tcpsock = psock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (pdbg_unlikely(tcpsock == INVALID_SOCKET))
    goto ex;
  setsockopt(tcpsock, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on));
  memset(&addr4, 0, sizeof(addr4));
  addr4.sin_family = AF_INET;
  addr4.sin_port = htons(0);
  addr4.sin_addr.s_addr = INADDR_ANY;
  if (pdbg_unlikely(bind(tcpsock, (struct sockaddr *)&addr4, sizeof(addr4)) ==
                   SOCKET_ERROR))
    goto ex;
  sl = sizeof(addr4);
  if (pdbg_unlikely(getsockname(tcpsock, (struct sockaddr *)&addr4, &sl) ==
                   SOCKET_ERROR))
    goto ex;
  tcpport = ntohs(addr4.sin_port);
  /*  }
    else{
      setsockopt(tcpsock, SOL_SOCKET, SO_REUSEADDR, (const char *)&on,
    sizeof(on)); memset(&addr, 0, sizeof(addr)); addr.sin6_family=AF_INET6;
      addr.sin6_port  =htons(0);
      addr.sin6_addr  =in6addr_any;
      if (pdbg_unlikely(bind(tcpsock, (struct sockaddr *)&addr,
    sizeof(addr))==SOCKET_ERROR)) goto ex; sl=sizeof(addr); if
    (pdbg_unlikely(getsockname(tcpsock, (struct sockaddr *)&addr,
    &sl)==SOCKET_ERROR)) goto ex; tcpport=ntohs(addr.sin6_port);
    }*/
  if (pdbg_unlikely(listen(tcpsock, 2)))
    goto ex;
  socks[0] = udpsock;
  socks[1] = tcpsock;
  while (psync_do_run) {
    if (unlikely(!psync_setting_get_bool(_PS(p2psync)))) {
      pthread_mutex_lock(&p2pmutex);
      if (!psync_setting_get_bool(_PS(p2psync))) {
        running = 0;
        close(tcpsock);
        close(udpsock);
        pthread_mutex_unlock(&p2pmutex);
        return;
      }
      pthread_mutex_unlock(&p2pmutex);
    }
    pstatus_wait_statuses_arr(requiredstatuses, ARRAY_SIZE(requiredstatuses));
    sret = psock_select_in(socks, 2, -1);
    if (pdbg_unlikely(sret == -1)) {
      psys_sleep_milliseconds(1);
      continue;
    }
    if (sret == 0) {
      paddrlen = sizeof(paddr);
      ret = recvfrom(udpsock, buff, sizeof(buff), 0, (struct sockaddr *)&paddr,
                     &paddrlen);
      if (pdbg_likely(ret != SOCKET_ERROR))
        psync_p2p_process_packet(buff, ret);
      else
        psys_sleep_milliseconds(1);
    } else if (sret == 1) {
      inconn = malloc(sizeof(int));
      *inconn = accept(tcpsock, NULL, NULL);
      if (pdbg_unlikely(*inconn == INVALID_SOCKET))
        free(inconn);
      else
        prun_thread1("p2p tcp", psync_p2p_tcphandler, inconn);
    }
  }
ex:
  pthread_mutex_lock(&p2pmutex);
  running = 0;
  close(tcpsock);
  close(udpsock);
  pthread_mutex_unlock(&p2pmutex);
}

static void psync_p2p_start() {
  pthread_mutex_lock(&p2pmutex);
  prun_thread("p2p", psync_p2p_thread);
  running = 1;
  pthread_mutex_unlock(&p2pmutex);
}

static void psync_p2p_wake() {
  int sock;
  struct sockaddr_in addr;
  packet_type_t pack;
  sock = psock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (pdbg_unlikely(sock == INVALID_SOCKET))
    return;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(PSYNC_P2P_PORT);
  addr.sin_addr.s_addr = htonl(0x7f000001UL);
  pack = P2P_WAKE;
  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != SOCKET_ERROR)
    pdbg_assertw(write(sock, &pack, sizeof(pack)) == sizeof(pack));
  close(sock);
}

void pp2p_init() {
  unsigned char computerbin[PSYNC_HASH_DIGEST_LEN];
  pssl_rand_strong(computerbin, PSYNC_HASH_DIGEST_LEN);
  psync_binhex(computername, computerbin, PSYNC_HASH_DIGEST_LEN);
  ptimer_exception_handler(psync_p2p_wake);
  if (!psync_setting_get_bool(_PS(p2psync)))
    return;
  psync_p2p_start();
}

void pp2p_change() {
  if (psync_setting_get_bool(_PS(p2psync)))
    psync_p2p_start();
  else
    psync_p2p_wake();
}

static int psync_p2p_check_rsa() {
  static pthread_mutex_t rsa_lock = PTHREAD_MUTEX_INITIALIZER;
  pthread_mutex_lock(&rsa_lock);
  if (privkey == PSYNC_INVALID_RSA) {
    psync_rsa_t rsa;
    psync_rsa_privatekey_t rsapriv;
    psync_rsa_publickey_t rsapub;
    psync_binary_rsa_key_t rsapubbin;
    pdbg_logf(D_NOTICE, "generating %ubit RSA key", PSYNC_P2P_RSA_SIZE);
    rsa = pssl_gen_rsa(PSYNC_P2P_RSA_SIZE);
    pdbg_logf(D_NOTICE, "key generated");
    if (pdbg_unlikely(rsa == PSYNC_INVALID_RSA))
      goto rete;
    rsapriv = prsa_get_private(rsa);
    rsapub = prsa_get_public(rsa);
    if (pdbg_likely(rsapub != PSYNC_INVALID_RSA))
      rsapubbin = prsa_public_to_binary(rsapub);
    else
      rsapubbin = PSYNC_INVALID_BIN_RSA;
    pssl_free_rsa(rsa);
    if (pdbg_likely(rsapriv != PSYNC_INVALID_RSA &&
                   rsapub != PSYNC_INVALID_RSA &&
                   rsapubbin != PSYNC_INVALID_BIN_RSA)) {
      pubkey = rsapriv;
      privkey = rsapub;
      pubkeybin = rsapubbin;
      goto ret0;
    } else {
      if (rsapriv != PSYNC_INVALID_RSA)
        prsa_free_private(rsapriv);
      if (rsapub != PSYNC_INVALID_RSA)
        prsa_free_public(rsapub);
      if (rsapubbin != PSYNC_INVALID_BIN_RSA)
        prsa_free_binary(rsapubbin);
      goto rete;
    }
  }
ret0:
  pthread_mutex_unlock(&rsa_lock);
  return 0;
rete:
  pthread_mutex_unlock(&rsa_lock);
  return -1;
}

static int psync_p2p_get_download_token(psync_fileid_t fileid,
                                        const unsigned char *filehashhex,
                                        uint64_t fsize, unsigned char **token,
                                        size_t *tlen) {
  binparam params[] = {
      PAPI_STR("auth", psync_my_auth), PAPI_NUM("fileid", fileid),
      PAPI_NUM("filesize", fsize),
      PAPI_LSTR(PSYNC_CHECKSUM, filehashhex, PSYNC_HASH_DIGEST_HEXLEN),
      PAPI_LSTR("keydata", pubkeybin->data,
             pubkeybin->datalen)};
  psock_t *api;
  binresult *res;
  const binresult *ctoken;
  *token = NULL; /* especially for gcc */
  *tlen = 0;
  api = psync_apipool_get();
  if (pdbg_unlikely(!api))
    return PSYNC_NET_TEMPFAIL;
  res = papi_send2(api, "getfileownershiptoken", params);
  if (pdbg_unlikely(!res)) {
    psync_apipool_release_bad(api);
    return PSYNC_NET_TEMPFAIL;
  }
  psync_apipool_release(api);
  if (pdbg_unlikely(papi_find_result2(res, "result", PARAM_NUM)->num != 0)) {
    free(res);
    return PSYNC_NET_PERMFAIL;
  }
  ctoken = papi_find_result2(res, "token", PARAM_STR);
  *token = malloc(ctoken->length + 1);
  memcpy(*token, ctoken->str, ctoken->length + 1);
  *tlen = ctoken->length;
  free(res);
  return PSYNC_NET_OK;
}

static int psync_p2p_download(int sock, psync_fileid_t fileid,
                              const unsigned char *filehashhex, uint64_t fsize,
                              const char *filename) {
  uint32_t keylen = 0, enctype = 0;
  psync_symmetric_key_t key;
  psync_encrypted_symmetric_key_t ekey;
  pcrypto_ctr_encdec_t decoder;
  psync_hash_ctx hashctx;
  uint64_t off;
  size_t rd;
  int fd;
  unsigned char buff[4096];
  unsigned char hashbin[PSYNC_HASH_DIGEST_LEN],
      hashhex[PSYNC_HASH_DIGEST_HEXLEN];
  if (pdbg_unlikely(socket_read_all(sock, &keylen, sizeof(keylen)) ||
                   socket_read_all(sock, &enctype, sizeof(enctype))))
    return PSYNC_NET_TEMPFAIL;
  if (enctype != P2P_ENCTYPE_RSA_AES) {
    pdbg_logf(D_ERROR, "unknown encryption type %u", (unsigned)enctype);
    return PSYNC_NET_PERMFAIL;
  }
  if (keylen > PSYNC_P2P_RSA_SIZE / 8 *
                   2) { /* PSYNC_P2P_RSA_SIZE/8 is enough actually */
    pdbg_logf(D_ERROR, "too long key - %u bytes", (unsigned)keylen);
    return PSYNC_NET_PERMFAIL;
  }
  ekey = psymkey_alloc_encrypted(keylen);
  if (pdbg_unlikely(socket_read_all(sock, ekey->data, keylen)) ||
      pdbg_unlikely((key = prsa_decrypt_symm_key_lock(
                        &privkey, &ekey)) == PSYNC_INVALID_SYM_KEY)) {
    // pdbg_unlikely((key=psymkey_decrypt(&psync_rsa_private,
    // &ekey))==PSYNC_INVALID_SYM_KEY)){
    free(ekey);
    return PSYNC_NET_TEMPFAIL;
  }
  free(ekey);
  decoder = pcrypto_ctr_encdec_create(key);
  psymkey_free(key);
  if (decoder == PSYNC_CRYPTO_INVALID_ENCODER)
    return PSYNC_NET_PERMFAIL;
  fd = pfile_open(filename, O_WRONLY, O_CREAT | O_TRUNC);
  if (unlikely(fd == INVALID_HANDLE_VALUE)) {
    pcrypto_ctr_encdec_free(decoder);
    pdbg_logf(D_ERROR, "could not open %s", filename);
    return PSYNC_NET_PERMFAIL;
  }
  off = 0;
  psync_hash_init(&hashctx);
  while (off < fsize) {
    if (fsize - off > sizeof(buff))
      rd = sizeof(buff);
    else
      rd = fsize - off;
    if (pdbg_unlikely(socket_read_all(sock, buff, rd)))
      goto err0;
    pcrypto_ctr_encdec_decode(decoder, buff, rd, off);
    if (pdbg_unlikely(pfile_write(fd, buff, rd) != rd))
      goto err0;
    psync_hash_update(&hashctx, buff, rd);
    off += rd;
  }
  pcrypto_ctr_encdec_free(decoder);
  pfile_close(fd);
  psync_hash_final(hashbin, &hashctx);
  psync_binhex(hashhex, hashbin, PSYNC_HASH_DIGEST_LEN);
  pdbg_logf(D_NOTICE, "downloaded file %s from peer", filename);
  if (memcmp(hashhex, filehashhex, PSYNC_HASH_DIGEST_HEXLEN)) {
    /* it is better to return permanent fail and let the block checksum algo to
     * find bad blocks */
    pdbg_logf(D_WARNING, "got bad checksum for file %s", filename);
    return PSYNC_NET_PERMFAIL;
  } else
    return PSYNC_NET_OK;
err0:
  pcrypto_ctr_encdec_free(decoder);
  pfile_close(fd);
  psync_hash_final(hashbin, &hashctx);
  return PSYNC_NET_TEMPFAIL;
}

int pp2p_check_download(psync_fileid_t fileid,
                             const unsigned char *filehashhex, uint64_t fsize,
                             const char *filename) {
  struct sockaddr_in6 addr;
  fd_set rfds;
  packet_check pct1;
  packet_get pct2;
  packet_check_resp resp;
  struct timeval tv;
  psock_ifaces_t *il;
  int *sockets;
  size_t i, tlen;
  int sock, msock;
  packet_resp_t bresp;
  unsigned char hashsource[PSYNC_HASH_BLOCK_SIZE],
      hashbin[PSYNC_HASH_DIGEST_LEN], hashhex[PSYNC_HASH_DIGEST_HEXLEN];
  unsigned char *token;
  socklen_t slen;
  int sret;
  if (!psync_setting_get_bool(_PS(p2psync)))
    return PSYNC_NET_PERMFAIL;
  pdbg_logf(D_NOTICE,
        "sending P2P_CHECK for file with hash %." NTO_STR(
            PSYNC_HASH_DIGEST_HEXLEN) "s",
        filehashhex);
  pct1.type = P2P_CHECK;
  memcpy(pct1.hashstart, filehashhex, PSYNC_P2P_HEXHASH_BYTES);
  pct1.filesize = fsize;
  pssl_rand_strong(pct1.rand, sizeof(pct1.rand));
  memcpy(hashsource, filehashhex, PSYNC_HASH_DIGEST_HEXLEN);
  memcpy(hashsource + PSYNC_HASH_DIGEST_HEXLEN, pct1.rand, sizeof(pct1.rand));
  psync_hash(hashsource, PSYNC_HASH_BLOCK_SIZE, hashbin);
  psync_binhex(pct1.genhash, hashbin, PSYNC_HASH_DIGEST_LEN);
  memcpy(pct1.computername, computername, PSYNC_HASH_DIGEST_HEXLEN);
  il = psock_list_adapters();
  sockets = malloc(sizeof(int) * il->interfacecnt);
  FD_ZERO(&rfds);
  msock = 0;
  for (i = 0; i < il->interfacecnt; i++) {
    sockets[i] = INVALID_SOCKET;
    sock = psock_create(il->interfaces[i].address.ss_family, SOCK_DGRAM,
                               IPPROTO_UDP);
    if (unlikely(sock == INVALID_SOCKET)) {
      pdbg_logf(D_NOTICE, "could not create a socket for address family %u",
            (unsigned)il->interfaces[i].address.ss_family);
      continue;
    }
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on));
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (const char *)&on, sizeof(on));
    if (pdbg_unlikely(bind(sock, (struct sockaddr *)&il->interfaces[i].address,
                          il->interfaces[i].addrsize) == SOCKET_ERROR)) {
      close(sock);
      continue;
    }
    if (il->interfaces[i].broadcast.ss_family == AF_INET)
      ((struct sockaddr_in *)(&il->interfaces[i].broadcast))->sin_port =
          htons(PSYNC_P2P_PORT);
    else if (il->interfaces[i].broadcast.ss_family == AF_INET6)
      ((struct sockaddr_in6 *)(&il->interfaces[i].broadcast))->sin6_port =
          htons(PSYNC_P2P_PORT);
    if (sendto(sock, (const char *)&pct1, sizeof(pct1), 0,
               (struct sockaddr *)&il->interfaces[i].broadcast,
               il->interfaces[i].addrsize) != SOCKET_ERROR) {
      sockets[i] = sock;
      FD_SET(sock, &rfds);
      if (sock >= msock)
        msock = sock + 1;
    } else
      close(sock);
  }
  if (pdbg_unlikely(!msock))
    goto err_perm;
  tv.tv_sec = PSYNC_P2P_INITIAL_TIMEOUT / 1000;
  tv.tv_usec = (PSYNC_P2P_INITIAL_TIMEOUT % 1000) * 1000;
  sret = select(msock, &rfds, NULL, NULL, &tv);
  if (sret == 0 || pdbg_unlikely(sret == SOCKET_ERROR))
    goto err_perm;
  bresp = P2P_RESP_NOPE;
  for (i = 0; i < il->interfacecnt; i++)
    if (sockets[i] != INVALID_SOCKET && FD_ISSET(sockets[i], &rfds)) {
      slen = sizeof(addr);
      sret = recvfrom(sockets[i], (char *)&resp, sizeof(resp), 0,
                      (struct sockaddr *)&addr, &slen);
      if (pdbg_unlikely(sret == SOCKET_ERROR) ||
          pdbg_unlikely(sret < sizeof(resp)))
        continue;
      if (!memcmp(pct1.rand, resp.rand, sizeof(resp.rand))) {
        pdbg_logf(
            D_WARNING,
            "clients are supposed to generate random data, not to reuse mine");
        continue;
      }
      memcpy(hashsource, filehashhex, PSYNC_HASH_DIGEST_HEXLEN);
      memcpy(hashsource + PSYNC_HASH_DIGEST_HEXLEN, resp.rand,
             sizeof(resp.rand));
      psync_hash(hashsource, PSYNC_HASH_BLOCK_SIZE, hashbin);
      psync_binhex(hashhex, hashbin, PSYNC_HASH_DIGEST_LEN);
      if (pdbg_unlikely(memcmp(hashhex, resp.genhash, PSYNC_HASH_DIGEST_HEXLEN)))
        continue;
      if (resp.type == P2P_RESP_HAVEIT) {
        pdbg_logf(D_NOTICE, "got P2P_RESP_HAVEIT");
        bresp = P2P_RESP_HAVEIT;
        break;
      } else if (resp.type == P2P_RESP_WAIT && bresp == P2P_RESP_NOPE)
        bresp = P2P_RESP_WAIT;
    }
  for (i = 0; i < il->interfacecnt; i++)
    if (sockets[i] != INVALID_SOCKET)
      close(sockets[i]);
  free(il);
  free(sockets);
  if (bresp == P2P_RESP_NOPE)
    goto err_perm2;
  else if (bresp == P2P_RESP_WAIT) {
    uint32_t rnd;
    pssl_rand_strong((unsigned char *)&rnd, sizeof(rnd));
    rnd &= 0x7ff;
    psys_sleep_milliseconds(PSYNC_P2P_SLEEP_WAIT_DOWNLOAD + rnd);
    goto err_temp2;
  }
  if (psync_p2p_check_rsa())
    goto err_perm2;
  sret =
      psync_p2p_get_download_token(fileid, filehashhex, fsize, &token, &tlen);
  pdbg_logf(D_NOTICE, "got token");
  if (pdbg_unlikely(sret != PSYNC_NET_OK)) {
    if (sret == PSYNC_NET_TEMPFAIL)
      goto err_temp2;
    else
      goto err_perm2;
  }
  if (addr.sin6_family == AF_INET6) {
    sock = psock_create(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    addr.sin6_port = htons(resp.port);
  } else if (addr.sin6_family == AF_INET) {
    sock = psock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ((struct sockaddr_in *)&addr)->sin_port = htons(resp.port);
  } else {
    pdbg_logf(D_ERROR, "unknown address family %u", (unsigned)addr.sin6_family);
    goto err_perm2;
  }
  if (pdbg_unlikely(sock == INVALID_SOCKET))
    goto err_perm3;
  if (unlikely(connect(sock, (struct sockaddr *)&addr, slen) == SOCKET_ERROR)) {
    pdbg_logf(D_WARNING, "could not connect to %s port %u", get_addr(&addr),
          (unsigned)resp.port);
    goto err_perm3;
  }
  pdbg_logf(D_NOTICE, "connected to peer");
  pct2.type = P2P_GET;
  memcpy(pct2.hashstart, filehashhex, PSYNC_P2P_HEXHASH_BYTES);
  pct2.filesize = fsize;
  pct2.keylen = pubkeybin->datalen;
  pct2.tokenlen = tlen;
  memcpy(pct2.rand, pct1.rand, sizeof(pct1.rand));
  memcpy(pct2.genhash, pct1.genhash, sizeof(pct1.genhash));
  memcpy(pct2.computername, computername, PSYNC_HASH_DIGEST_HEXLEN);
  if (socket_write_all(sock, &pct2, sizeof(pct2)) ||
      socket_write_all(sock, pubkeybin->data,
                       pubkeybin->datalen) ||
      socket_write_all(sock, token, tlen)) {
    pdbg_logf(D_WARNING, "writing to socket failed");
    goto err_temp3;
  }
  free(token);
  sret = psync_p2p_download(sock, fileid, filehashhex, fsize, filename);
  close(sock);
  return sret;
err_perm3:
  free(token);
  goto err_perm2;
err_perm:
  for (i = 0; i < il->interfacecnt; i++)
    if (sockets[i] != INVALID_SOCKET)
      close(sockets[i]);
  free(il);
  free(sockets);
err_perm2:
  return PSYNC_NET_PERMFAIL;
err_temp3:
  close(sock);
  free(token);
err_temp2:
  return PSYNC_NET_TEMPFAIL;
}
