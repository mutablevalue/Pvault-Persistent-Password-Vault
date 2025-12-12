#define _GNU_SOURCE
#include "socket.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static const char *GetSocketPath(void) {
  const char *XdgRuntimeDir = getenv("XDG_RUNTIME_DIR");
  if (!XdgRuntimeDir || !XdgRuntimeDir[0]) {
    fprintf(stderr,
            "XDG_RUNTIME_DIR is not set; cannot create daemon socket\n");
    return NULL;
  }

  static char Path[512];
  snprintf(Path, sizeof(Path), "%s/pvault.sock", XdgRuntimeDir);
  return Path;
}

int ConnectToDaemon(void) {
  const char *Path = GetSocketPath();
  if (!Path)
    return -1;

  int Socket = socket(AF_UNIX, SOCK_STREAM, 0);
  if (Socket < 0)
    return -1;

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, Path, sizeof(addr.sun_path) - 1);

  if (connect(Socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    close(Socket);
    return -1;
  }

  return Socket;
}

int EnsureListener(void) {
  const char *Path = GetSocketPath();
  if (!Path)
    return -1;

  int Socket = socket(AF_UNIX, SOCK_STREAM, 0);
  if (Socket < 0)
    return -1;

  unlink(Path);

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, Path, sizeof(addr.sun_path) - 1);

  if (bind(Socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    close(Socket);
    return -1;
  }
  chmod(Path, 0600);

  if (listen(Socket, 16) < 0) {
    close(Socket);
    return -1;
  }

  return Socket;
}
