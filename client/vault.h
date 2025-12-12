#pragma once
#include "../utils/input.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
} Vault;

void Init(Vault *Current, int argc, char **argv);
void Close(Vault *Current);
