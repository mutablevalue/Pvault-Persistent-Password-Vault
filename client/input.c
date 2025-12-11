#include "../client/input.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

Options Parse(int argc, char **argv) {
  Options Option = {.CurrentMode = NONE, .Target = NULL};

  if (argc < 1)
    return Option;

  if (strcmp(argv[1], "--add") == 0) {
    if (argc < 3)
      return Option;
    Option.CurrentMode = ADD;
    Option.Target = argv[2];
  } else if (strcmp(argv[1], "--remove") == 0) {
    if (argc < 3)
      return Option;
    Option.CurrentMode = REMOVE;
    Option.Target = argv[2];
  } else if (strcmp(argv[1], "--find") == 0) {
    if (argc < 3)
      return Option;
    Option.CurrentMode = FIND;
    Option.Target = argv[2];
  } else if (strcmp(argv[1], "--list") == 0) {
    if (argc >= 3)
      Option.Target = argv[2];
    Option.CurrentMode = LIST;
  } else if (strcmp(argv[1], "--dump") == 0) {
    if (argc > 2)
      return Option;
    Option.CurrentMode = DUMP;
  }

  return Option;
}
