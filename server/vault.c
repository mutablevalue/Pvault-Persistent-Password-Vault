#include "../server/vault.h"
#include "../daemon/daemon.h"
#include <unistd.h>
Entry CreateEntry();

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

  if (WriteLine(StartDriver, "PING") < 0) {
    printf("Failed to write to daemon\n");
    close(StartDriver);
    return;
  }

  char buf[512];
  if (ReadLine(StartDriver, buf, sizeof(buf)) <= 0) {
    printf("Failed to read from daemon\n");
    close(StartDriver);
    return;
  }

  close(StartDriver);
  (void)Current;
}
void AddEntry(Vault *Current, const char *Value);
void RemoveEntry(Vault *Current, const char *Value);
void DumpEntries(const Vault *Current);
void ListEntries(const Vault *Current, const char *Value);
void UpdateEntry(Vault *Current, const char *Value);
Entry *GetEntry(Vault *Current, const char *Value);
const Entry *FindEntry(const Vault *Current, const char *Value);
void Close(Vault *Current) { (void)Current; }
