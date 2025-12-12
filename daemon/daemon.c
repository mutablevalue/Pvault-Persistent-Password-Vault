#include "daemon.h"
#include "../daemon/crypto.h"
#include "socket.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
static CryptoContext GCtx; // global context

static void HandleClient(int Client) {
  char Buffer[512];

  for (;;) {
    ssize_t count = ReadLine(Client, Buffer, sizeof(Buffer));
    if (count <= 0) {
      break; // client closed or error
    }

    char *cmd = strtok(Buffer, " ");
    char *arg = strtok(NULL, "");

    if (!cmd) {
      WriteLine(Client, "Error: Empty");
      continue;
    }

    if (strcmp(cmd, "ENSURE_UNLOCK") == 0) {
      if (CryptoEnsureUnlocked(&GCtx) == 0) {
        WriteLine(Client, "OK");
      } else {
        WriteLine(Client, "ERR unlock-failed");
      }
      continue;
    }

    if (!CryptoIsUnlocked(&GCtx)) {
      WriteLine(Client, "ERR locked");
      continue;
    }

    if (strcmp(cmd, "ADD") == 0) {
      if (!arg || !*arg) {
        WriteLine(Client, "ERR missing-name");
        continue;
      }
      if (CryptoAddEntry(&GCtx, arg) == 0) {
        WriteLine(Client, "OK");
      } else {
        WriteLine(Client, "ERR add-failed");
      }
      continue;
    }

    if (strcmp(cmd, "REMOVE") == 0) {
      if (!arg || !*arg) {
        WriteLine(Client, "ERR missing-name");
        continue;
      }
      if (CryptoRemoveEntry(&GCtx, arg) == 0) {
        WriteLine(Client, "OK");
      } else {
        WriteLine(Client, "NOT_FOUND");
      }
      continue;
    }

    if (strcmp(cmd, "FIND") == 0) {
      if (!arg || !*arg) {
        WriteLine(Client, "ERR missing-name");
        continue;
      }
      if (CryptoFindEntry(&GCtx, arg) == 0) {
        WriteLine(Client, "FOUND");
      } else {
        WriteLine(Client, "NOT_FOUND");
      }
      continue;
    }

    if (strcmp(cmd, "LIST") == 0) {
      CryptoListEntries(&GCtx, arg ? arg : "");
      WriteLine(Client, "OK");
      continue;
    }

    if (strcmp(cmd, "DUMP") == 0) {
      CryptoDumpEntries(&GCtx);
      WriteLine(Client, "OK");
      continue;
    }

    WriteLine(Client, "ERR unknown-command");
  }
}

static void Loop(int Listener) {
  CryptoInitContext(&GCtx);
  if (CryptoLoadVault(&GCtx) != 0) {
    fprintf(stderr, "Failed to load vault file\n");
    _exit(1);
  }
  for (;;) {
    int Client = accept(Listener, NULL, NULL);
    if (Client < 0)
      continue;
    HandleClient(Client);
    close(Client);
  }

  CryptoFreeContext(&GCtx);
}

void StartService(int Listener) { Loop(Listener); }
ssize_t ReadLine(int Socket, char *Buffer, size_t Size) {
  if (!Buffer || Size == 0)
    return -1;
  size_t Position = 0;
  char Current;

  for (;;) {
    ssize_t Count = read(Socket, &Current, 1);

    if (Count <= 0) {
      Buffer[Position] = '\0';
      return -1;
    }
    if (Current == '\r')
      continue;
    if (Current == '\n')
      break;
    if (Position + 1 < Size) {
      Buffer[Position++] = Current;
    } else {
      continue;
    }
  }

  Buffer[Position] = '\0';
  return (ssize_t)Position;
}
int WriteLine(int Socket, const char *Buffer) {

  if (!Buffer)
    return -1;
  size_t Length = strlen(Buffer);
  ssize_t Count;

  while (Length > 0) {
    Count = write(Socket, Buffer, Length);
    if (Count < 0)
      return -1;
    Buffer += Count;
    Length -= Count;
  }

  Count = write(Socket, "\n", 1);
  if (Count != 1)
    return 1;
  return 0;
}
int EnsureDaemon(void) {
  int Attempt = ConnectToDaemon();
  if (Attempt >= 0)
    return Attempt; // Daemon has already been created

  int Pipes[2];
  if (pipe(Pipes) < 0) {
    perror("Piping issue with Daemon");
    return -1;
  }

  pid_t PID = fork();
  if (PID < 0) {
    perror("Coudlnt get this processes, process id");
    close(Pipes[0]);
    close(Pipes[1]);
    return -1;
  }
  if (PID == 0) {
    close(Pipes[0]);

    if (setsid() < 0)
      _exit(1);

    int Listener = EnsureListener();
    if (Listener < 0) {
      close(Pipes[1]);
      _exit(1);
    }
    char c = 'R';
    write(Pipes[1], &c, 1);
    close(Pipes[1]);
    StartService(Listener);
    _exit(0);
  }

  close(Pipes[1]);
  char Sig;
  ssize_t count = read(Pipes[0], &Sig, 1);
  close(Pipes[0]);
  if (count != 1 || Sig != 'R') {
    fprintf(stderr, "Daemon failed to start\n");
    return -1;
  }

  Attempt = ConnectToDaemon();
  if (Attempt < 0) {
    fprintf(stderr, "Could not connect to daemon after ready signal\n");
  }
  return Attempt;
}
