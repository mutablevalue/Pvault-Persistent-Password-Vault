#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { ADD, REMOVE, FIND, LIST, DUMP, NONE } Mode;

typedef struct {
  Mode CurrentMode;
  const char *Target;
} Options;

Mode GetMode(Options *Current);
const Mode FindMode(const Options *Current);
Options Parse(int argc, char **argv);
void UpdateMode(Options *Current, const Mode *New);
