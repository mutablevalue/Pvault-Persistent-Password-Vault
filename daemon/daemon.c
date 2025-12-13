#include "daemon.h"
#include "crypto.h"
#include "socket.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static CryptoContext GlobalContext;

ssize_t ReadLine(int SocketFd, char *Buffer, size_t Size) {
  if (!Buffer || Size == 0)
    return -1;

  size_t Position = 0;
  char Current;

  for (;;) {
    ssize_t Count = read(SocketFd, &Current, 1);
    if (Count <= 0) {
      Buffer[Position] = '\0';
      return -1;
    }

    if (Current == '\r')
      continue;
    if (Current == '\n')
      break;

    if (Position + 1 < Size)
      Buffer[Position++] = Current;
  }

  Buffer[Position] = '\0';
  return (ssize_t)Position;
}

int WriteLine(int SocketFd, const char *Buffer) {
  if (!Buffer)
    return -1;

  size_t Length = strlen(Buffer);
  while (Length > 0) {
    ssize_t Written = write(SocketFd, Buffer, Length);
    if (Written < 0)
      return -1;
    Buffer += Written;
    Length -= (size_t)Written;
  }

  return write(SocketFd, "\n", 1) == 1 ? 0 : -1;
}

static void HandleClient(int ClientFd) {
  char Buffer[512];

  for (;;) {
    ssize_t Count = ReadLine(ClientFd, Buffer, sizeof(Buffer));
    if (Count <= 0)
      break;

    char *Command = strtok(Buffer, " ");
    char *Argument = strtok(NULL, "");

    if (!Command) {
      WriteLine(ClientFd, "ERR empty");
      continue;
    }

    /* Handshake: daemon never prompts */
    if (strcmp(Command, "ENSURE_UNLOCK") == 0) {
      if (CryptoIsUnlocked(&GlobalContext)) {
        WriteLine(ClientFd, "OK");
      } else if (CryptoHasMaster(&GlobalContext)) {
        WriteLine(ClientFd, "NEED_PASSWORD");
      } else {
        WriteLine(ClientFd, "NEED_CREATE");
      }
      continue;
    }

    if (strcmp(Command, "UNLOCK") == 0) {
      if (!Argument || !Argument[0]) {
        WriteLine(ClientFd, "ERR unlock_missing");
        continue;
      }
      if (CryptoUnlockWithPassword(&GlobalContext, Argument) == 0) {
        WriteLine(ClientFd, "OK");
      } else {
        WriteLine(ClientFd, "ERR unlock_failed");
      }
      continue;
    }

    if (strcmp(Command, "CREATE_MASTER") == 0) {
      if (!Argument || !Argument[0]) {
        WriteLine(ClientFd, "ERR create_missing");
        continue;
      }
      if (CryptoCreateMasterWithPassword(&GlobalContext, Argument) == 0) {
        WriteLine(ClientFd, "OK");
      } else {
        WriteLine(ClientFd, "ERR create_failed");
      }
      continue;
    }

    /* Everything below requires unlocked */
    if (!CryptoIsUnlocked(&GlobalContext)) {
      WriteLine(ClientFd, "ERR locked");
      continue;
    }

    if (strcmp(Command, "ADD") == 0) {
      WriteLine(ClientFd,
                Argument && CryptoAddEntry(&GlobalContext, Argument) == 0
                    ? "OK"
                    : "ERR add");
      continue;
    }

    if (strcmp(Command, "REMOVE") == 0) {
      int R = (Argument ? CryptoRemoveEntry(&GlobalContext, Argument) : -1);
      if (R == 0)
        WriteLine(ClientFd, "OK");
      else
        WriteLine(ClientFd, "NOT_FOUND");
      continue;
    }

    if (strcmp(Command, "FIND") == 0) {
      int R = (Argument
                   ? CryptoFindEntryToSocket(&GlobalContext, Argument, ClientFd)
                   : -1);
      if (R == 0)
        WriteLine(ClientFd, "OK");
      else if (R == -2)
        WriteLine(ClientFd, "NOT_FOUND");
      else
        WriteLine(ClientFd, "ERR find");
      continue;
    }

    if (strcmp(Command, "LIST") == 0) {
      if (CryptoListEntriesToSocket(&GlobalContext, Argument ? Argument : "",
                                    ClientFd) == 0)
        WriteLine(ClientFd, "OK");
      else
        WriteLine(ClientFd, "ERR list");
      continue;
    }

    if (strcmp(Command, "DUMP") == 0) {
      char *Path = NULL;
      if (CryptoDumpEntriesDecrypted(&GlobalContext, &Path) == 0 && Path) {
        char Line[1024];
        snprintf(Line, sizeof(Line), "DATA %s", Path);
        WriteLine(ClientFd, "DATA DumpPath:");
        WriteLine(ClientFd, Line);
        free(Path);
        WriteLine(ClientFd, "OK");
      } else {
        if (Path)
          free(Path);
        WriteLine(ClientFd, "ERR dump");
      }
      continue;
    }

    WriteLine(ClientFd, "ERR unknown");
  }
}

void StartService(int ListenerFd) {
  CryptoInitContext(&GlobalContext);
  if (CryptoLoadVault(&GlobalContext) != 0)
    _exit(1);

  for (;;) {
    int ClientFd = accept(ListenerFd, NULL, NULL);
    if (ClientFd < 0)
      continue;
    HandleClient(ClientFd);
    close(ClientFd);
  }
}

int EnsureDaemon(void) {
  int SocketFd = ConnectToDaemon();
  if (SocketFd >= 0)
    return SocketFd;

  int PipeFds[2];
  if (pipe(PipeFds) < 0)
    return -1;

  pid_t Pid = fork();
  if (Pid < 0)
    return -1;

  if (Pid == 0) {
    close(PipeFds[0]);
    setsid();

    int ListenerFd = EnsureListener();
    if (ListenerFd < 0)
      _exit(1);

    char Ready = 'R';
    write(PipeFds[1], &Ready, 1);
    close(PipeFds[1]);

    StartService(ListenerFd);
    _exit(0);
  }

  close(PipeFds[1]);
  char Signal;
  if (read(PipeFds[0], &Signal, 1) != 1 || Signal != 'R')
    return -1;
  close(PipeFds[0]);

  return ConnectToDaemon();
}
