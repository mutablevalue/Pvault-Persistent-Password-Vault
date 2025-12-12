#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { ADD, REMOVE, FIND, LIST, DUMP, NONE } Mode;

typedef struct {
  Mode CurrentMode;
  const char *Target;
} Options;

Options Parse(int argc, char **argv);
