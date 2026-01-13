#include "input.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

Options Parse(int argc, char **argv) {
  Options Option = {
      .CurrentMode = NONE, .Target = NULL, .Field = NULL, .Value = NULL};

  if (argc < 2 || argc > 5)
    return Option;

  if (strcmp(argv[1], "--add") == 0) {
    if (argc != 3)
      return Option;
    Option.CurrentMode = ADD;
    Option.Target = argv[2];

  } else if (strcmp(argv[1], "--remove") == 0) {
    if (argc != 3)
      return Option;
    Option.CurrentMode = REMOVE;
    Option.Target = argv[2];

  } else if (strcmp(argv[1], "--find") == 0) {
    if (argc != 3)
      return Option;
    Option.CurrentMode = FIND;
    Option.Target = argv[2];

  } else if (strcmp(argv[1], "--list") == 0) {
    if (argc == 3)
      Option.Target = argv[2];
    else if (argc != 2)
      return Option;
    Option.CurrentMode = LIST;

  } else if (strcmp(argv[1], "--dump") == 0) {
    if (argc != 2)
      return Option;
    Option.CurrentMode = DUMP;

  } else if (strcmp(argv[1], "--help") == 0) {
    if (argc != 2)
      return Option;
    Option.CurrentMode = HELP;

  } else if (strcmp(argv[1], "--update") == 0) {
    if (argc != 5)
      return Option;
    Option.CurrentMode = UPDATE;
    Option.Target = argv[2];
    Option.Field = argv[3];
    Option.Value = argv[4];
  }

  return Option;
}
