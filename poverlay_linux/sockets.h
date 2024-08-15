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

#ifndef SOCKETS_H_INCLUDED
#define SOCKETS_H_INCLUDED

#if !defined(MINGW) && !defined(_WIN32)

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#else

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

#include <Ws2tcpip.h>
#include <winsock2.h>

#ifndef AI_ADDRCONFIG
#define AI_ADDRCONFIG 0x0001
#endif

#ifndef AI_ALL
#define AI_ALL 0x0002
#endif

#ifndef AI_CANONNAME
#define AI_CANONNAME 0x0004
#endif

#ifndef AI_NUMERICHOST
#define AI_NUMERICHOST 0x0008
#endif

#ifndef AI_NUMERICSERV
#define AI_NUMERICSERV 0x0010
#endif

#ifndef AI_PASSIVE
#define AI_PASSIVE 0x0020
#endif

#ifndef AI_V4MAPPED
#define AI_V4MAPPED 0x0040
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK WSAEWOULDBLOCK
#endif

#endif

#endif // SOCKETS_H_INCLUDED
