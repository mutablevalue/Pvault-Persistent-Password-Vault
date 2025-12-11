#include "server/vault.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {

  Vault V;
  Init(&V, argc, argv);

  Close(&V);
}
