#pragma once
#include "../utils/input.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  int Unused;
} Vault;

void Init(Vault *Current, int argc, char **argv);
void Close(Vault *Current);
