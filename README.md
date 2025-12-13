# pvault

`pvault` is a local password manager written in C.  
It encrypts all stored credentials using libsodium and runs a background daemon so the vault only needs to be unlocked once per session.

The tool is designed to be simple, local-only, and transparent.

---

## Summary

- All data is stored encrypted on disk
- A background daemon keeps the vault unlocked in memory
- Commands communicate with the daemon over a UNIX socket
- No network access and no external services

---

## How It Works

1. You run a `pvault` command
2. If the daemon is not running, it is started automatically
3. The daemon checks whether the vault is unlocked
4. If needed, the client prompts for the master password
5. The requested operation is performed by the daemon

The daemon never reads from stdin. All user input happens in the client.

---

## Vault Location

The encrypted vault file is stored at:



$XDG_DATA_HOME/pvault/vault.dat


If `XDG_DATA_HOME` is not set, it defaults to:



~/.local/share/pvault/vault.dat


---

## Commands

### Add an entry
```bash
pvault --add SERVICE


Prompts for:

username (optional)

password (press enter to auto-generate)

link (optional)

If the service already exists, it is replaced.

Find an entry
pvault --find SERVICE


Prints:

service

username

password

link

Remove an entry
pvault --remove SERVICE


Deletes the entry for the given service.

List entries
pvault --list
pvault --list all
pvault --list N


No argument: list up to 5 entries

all: list every entry

N: list the first N entries

Dump decrypted vault
pvault --dump


Creates a plaintext dump of all entries in:

~/Downloads/pvault_dump_XXXXXX.txt


This file is decrypted and should be handled carefully.

Installation
Build
gcc -std=c11 -Wall -Wextra -O2 \
  $(find . -name '*.c') \
  -o pvault -lsodium
