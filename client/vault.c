#include "../client/vault.h"
#include "../daemon/daemon.h"
#include <unistd.h>

void Init(Vault *Current, int argc, char **argv) {
  Options Option = Parse(argc, argv);
  if (Option.CurrentMode == NONE) {
    printf("Incorrect Command Usage");
    return;
  }

  int StartDriver = EnsureDaemon();
  if (StartDriver < 0) {
    printf("Daemon didn't start");
    return;
  }

  char Request[512];
  char Response[512];

  snprintf(Request, sizeof(Request), "ENSURE_UNLOCK");

  if (WriteLine(StartDriver, Request) < 0) {
    printf("Failed to write ENSURE_UNLOCK\n");
    close(StartDriver);
    return;
  }
  if (ReadLine(StartDriver, Response, sizeof(Response)) <= 0) {
    printf("No response from daemon on ENSURE_UNLOCK\n");
    close(StartDriver);
    return;
  }

  if (strcmp(Response, "OK") != 0) {
    printf("Daemon failed to unlock: %s\n", Response);
    close(StartDriver);
    return;
  }

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
    if (Option.Target && Option.Target[0] != '\0') {
      snprintf(Request, sizeof(Request), "LIST %s", Option.Target);
    } else {
      snprintf(Request, sizeof(Request), "LIST");
    }
    break;
  case DUMP:
    snprintf(Request, sizeof(Request), "DUMP");
    break;
  default:
    close(StartDriver);
    return;
  }

  if (WriteLine(StartDriver, Request) < 0) {
    printf("Failed to write to daemon");
    close(StartDriver);
    return;
  }

  ssize_t count = ReadLine(StartDriver, Response, sizeof(Response));
  if (count <= 0) {
    printf("Failed to read from daemon\n");
    close(StartDriver);
    return;
  }
  printf("Response: %s\n", Response);
  close(StartDriver);
  (void)Current;
}
void Close(Vault *Current) { (void)Current; }
