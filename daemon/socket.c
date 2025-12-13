#define _GNU_SOURCE
#include "socket.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static const char *GetSocketPath(void) {
  const char *RuntimeDir = getenv("XDG_RUNTIME_DIR");
  if (!RuntimeDir || !RuntimeDir[0])
    RuntimeDir = "/tmp";

  static char SocketPath[512];
  int Written =
      snprintf(SocketPath, sizeof(SocketPath), "%s/pvault.sock", RuntimeDir);
  if (Written < 0 || (size_t)Written >= sizeof(SocketPath))
    return NULL;

  return SocketPath;
}

static socklen_t UnixSockaddrLength(const struct sockaddr_un *Address) {
  return (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                     strlen(Address->sun_path) + 1);
}

int ConnectToDaemon(void) {
  const char *SocketPath = GetSocketPath();
  if (!SocketPath)
    return -1;

  int SocketFd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (SocketFd < 0)
    return -1;

  struct sockaddr_un Address;
  memset(&Address, 0, sizeof(Address));
  Address.sun_family = AF_UNIX;
  if (strlen(SocketPath) >= sizeof(Address.sun_path))
    return -1;
  snprintf(Address.sun_path, sizeof(Address.sun_path), "%s", SocketPath);
  if (connect(SocketFd, (struct sockaddr *)&Address,
              UnixSockaddrLength(&Address)) < 0) {
    close(SocketFd);
    return -1;
  }

  return SocketFd;
}

int EnsureListener(void) {
  const char *SocketPath = GetSocketPath();
  if (!SocketPath)
    return -1;

  int SocketFd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (SocketFd < 0)
    return -1;

  unlink(SocketPath);

  struct sockaddr_un Address;
  memset(&Address, 0, sizeof(Address));
  Address.sun_family = AF_UNIX;
  if (strlen(SocketPath) >= sizeof(Address.sun_path))
    return -1;
  snprintf(Address.sun_path, sizeof(Address.sun_path), "%s", SocketPath);
  if (bind(SocketFd, (struct sockaddr *)&Address,
           UnixSockaddrLength(&Address)) < 0) {
    close(SocketFd);
    return -1;
  }

  chmod(SocketPath, 0600);

  if (listen(SocketFd, 16) < 0) {
    close(SocketFd);
    return -1;
  }

  return SocketFd;
}
