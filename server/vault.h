#pragma once
#include "../client/input.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  char *Name;
  char *Username;
  char *Password;
  char *URL;
} Entry;

Entry CreateEntry();

typedef struct {
  Entry *Entries;
  size_t Count;
  int is_unlocked;
} Vault;

void Init(Vault *Current, int argc, char **argv);
void AddEntry(Vault *Current, const char *Value);
void RemoveEntry(Vault *Current, const char *Value);
void DumpEntries(const Vault *Current);
void UpdateEntry(Vault *Current, const char *Value);
void ListEntries(const Vault *Current, const char *Value);
Entry *GetEntry(Vault *Current, const char *Value);
const Entry *FindEntry(const Vault *Current, const char *Value);
void Close(Vault *Current);
