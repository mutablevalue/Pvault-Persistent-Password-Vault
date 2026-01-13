#include "../client/vault.h"
#include "../daemon/daemon.h"

#include "../client/message.c"
#include "../daemon/helpers.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void ZeroBuffer(void *Ptr, size_t Len) {
  volatile unsigned char *P = (volatile unsigned char *)Ptr;
  while (Len--)
    *P++ = 0;
}

static int SendRequestAndReadUntilTerminal(int Socket, const char *Request) {
  char Response[512];

  if (WriteLine(Socket, Request) < 0)
    return -1;

  for (;;) {
    ssize_t ReadCount = ReadLine(Socket, Response, sizeof(Response));
    if (ReadCount <= 0)
      return -1;

    if (strcmp(Response, "OK") == 0)
      return 0;

    if (strcmp(Response, "MESSAGE") == 0) {
      fputs(GetMessage(), stdout);
      return 0;
    }

    if (strcmp(Response, "NOT_FOUND") == 0)
      return -2;

    if (strncmp(Response, "ERR", 3) == 0) {
      fprintf(stderr, "%s\n", Response);
      return -1;
    }

    if (strncmp(Response, "DATA ", 5) == 0) {
      printf("%s\n", Response + 5);
      continue;
    }

    fprintf(stderr, "ERR unexpected: %s\n", Response);
    return -1;
  }
}

static int EnsureUnlockedOverDaemon(int Socket) {
  char Response[512];

  if (WriteLine(Socket, "ENSURE_UNLOCK") < 0)
    return -1;

  if (ReadLine(Socket, Response, sizeof(Response)) <= 0)
    return -1;

  if (strcmp(Response, "OK") == 0)
    return 0;

  if (strcmp(Response, "NEED_PASSWORD") == 0) {
    char Password[256];
    if (PromptUser("Enter Master Password", Password, sizeof(Password)) != 0)
      return -1;

    char Req[600];
    snprintf(Req, sizeof(Req), "UNLOCK %s", Password);
    ZeroBuffer(Password, sizeof(Password));

    return SendRequestAndReadUntilTerminal(Socket, Req);
  }

  if (strcmp(Response, "NEED_CREATE") == 0) {
    char P1[256];
    char P2[256];

    for (;;) {
      if (PromptUser("Create master password", P1, sizeof(P1)) != 0)
        return -1;
      if (PromptUser("Confirm master password", P2, sizeof(P2)) != 0)
        return -1;
      if (strcmp(P1, P2) == 0)
        break;

      fprintf(stderr, "Passwords do not match\n");
      ZeroBuffer(P1, sizeof(P1));
      ZeroBuffer(P2, sizeof(P2));
    }

    char Req[600];
    snprintf(Req, sizeof(Req), "CREATE_MASTER %s", P1);
    ZeroBuffer(P1, sizeof(P1));
    ZeroBuffer(P2, sizeof(P2));

    return SendRequestAndReadUntilTerminal(Socket, Req);
  }

  fprintf(stderr, "ERR unexpected unlock response: %s\n", Response);
  return -1;
}

void Init(Vault *Current, int ArgCount, char **ArgValues) {
  Options Option = Parse(ArgCount, ArgValues);
  if (Option.CurrentMode == NONE) {
    printf("Incorrect Command Usage\n");
    return;
  }

  int Socket = EnsureDaemon();
  if (Socket < 0) {
    printf("Daemon didn't start\n");
    return;
  }

  if (EnsureUnlockedOverDaemon(Socket) != 0) {
    printf("Daemon failed to unlock\n");
    close(Socket);
    return;
  }

  char Request[512];

  switch (Option.CurrentMode) {
  case ADD:
    snprintf(Request, sizeof(Request), "ADD %s", Option.Target);
    break;
  case REMOVE:
    snprintf(Request, sizeof(Request), "REMOVE %s", Option.Target);
    break;
  case FIND:
    snprintf(Request, sizeof(Request), "FIND %s", Option.Target);
    break;
  case LIST:
    if (Option.Target && Option.Target[0])
      snprintf(Request, sizeof(Request), "LIST %s", Option.Target);
    else
      snprintf(Request, sizeof(Request), "LIST");
    break;
  case DUMP:
    snprintf(Request, sizeof(Request), "DUMP");
    break;
  case HELP:
    snprintf(Request, sizeof(Request), "HELP");
    break;
  case UPDATE:
    snprintf(Request, sizeof(Request), "UPDATE %s %s %s", Option.Target,
             Option.Field, Option.Value);
    break;
  default:
    close(Socket);
    return;
  }

  int Result = SendRequestAndReadUntilTerminal(Socket, Request);
  if (Result == -2)
    printf("NOT_FOUND\n");

  close(Socket);
  (void)Current;
}

void Close(Vault *Current) { (void)Current; }
