#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { ADD, REMOVE, FIND, LIST, DUMP, NONE } Mode;
// possible inputs
typedef struct {
  Mode CurrentMode;
  const char *Target;
} Options;
// target is the arg
Options Parse(int argc, char **argv);
