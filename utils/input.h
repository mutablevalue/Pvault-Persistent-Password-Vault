#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { ADD, REMOVE, HELP, FIND, LIST, DUMP, NONE, UPDATE } Mode;
// possible inputs
typedef struct {
  Mode CurrentMode;
  const char *Target;
  const char *Field;
  const char *Value;
} Options;
// target is the arg
Options Parse(int argc, char **argv);
