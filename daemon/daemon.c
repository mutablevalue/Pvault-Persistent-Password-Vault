#include "daemon.h"
#include "socket.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static void Loop(int Listener) {
  for (;;) {
    int Client = accept(Listener, NULL, NULL);
    if (Client < 0) {
      continue;
    }
    char Buffer[512];
    ssize_t Count = ReadLine(Client, Buffer, sizeof(Buffer));
    if (Count > 0) {
      if (strcmp(Buffer, "PING") == 0) {
        WriteLine(Client, "PONG");
      } else {
        WriteLine(Client, "UNKNOWN");
      }
    }
    close(Client);
  }
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
