pvault - Persistent Password Vault
================================

pvault is a local, CLI-based password manager written in C.
It encrypts all credentials using libsodium and uses a background daemon
to keep the vault unlocked for the duration of a user session.

The project is intentionally local-only and avoids network access,
external services, or cloud dependencies.

------------------------------------------------------------
Summary
------------------------------------------------------------

- Written in C for Linux
- Encrypted vault stored on disk
- Background daemon keeps secrets unlocked in memory
- Client communicates with daemon over a UNIX domain socket
- Uses XDG-compliant paths
- No network access

------------------------------------------------------------
Threat Model
------------------------------------------------------------

pvault is designed to protect against:

- Offline attackers who obtain a copy of the encrypted vault file
- Accidental credential exposure via plaintext files
- Other unprivileged users on the same system (with proper permissions)

pvault does NOT protect against:

- An attacker with root access
- A compromised kernel
- Malicious code running as the same user
- Memory inspection attacks while the vault is unlocked

This project prioritizes usability and simplicity over maximum resistance
to advanced local attackers.

------------------------------------------------------------
How It Works
------------------------------------------------------------

1. A pvault client command is executed
2. The client checks if the daemon is running
3. If not running, the daemon is started automatically
4. The client communicates with the daemon over a UNIX socket
5. If the vault is locked, the client prompts for the master password
6. The daemon decrypts the vault into memory
7. Subsequent commands reuse the unlocked in-memory state

The daemon never reads from stdin.
All user interaction happens in the client.

------------------------------------------------------------
Security Design
------------------------------------------------------------

Encryption
- libsodium is used for all cryptographic operations
- A password-based key derivation function (KDF) derives the master key
- Each vault entry is encrypted using an AEAD construction
- Nonces are generated securely and stored with ciphertext
- Vault format includes versioning for future upgrades

Memory Handling
- Secrets exist in plaintext only while the vault is unlocked
- Sensitive buffers are wiped using sodium_memzero when no longer needed
- The daemon holds decrypted data only in process memory

------------------------------------------------------------
Daemon & IPC Security
------------------------------------------------------------

- Communication uses a UNIX domain socket
- Socket is created under XDG_RUNTIME_DIR or /tmp as fallback
- Socket permissions are restricted to the current user
- Only local clients owned by the same UID can connect
- No network sockets are opened

------------------------------------------------------------
Auto-Locking & Lifecycle
------------------------------------------------------------

- Vault unlock state exists only while the daemon is running
- Restarting the system or killing the daemon locks the vault
- Future improvements may include:
  - Idle timeout auto-lock
  - Explicit lock command
  - systemd user service integration

------------------------------------------------------------
Vault Location
------------------------------------------------------------

Encrypted vault file:

  $XDG_DATA_HOME/pvault/vault
  (fallback: $HOME/.local/share/pvault/vault)

Runtime socket:

  $XDG_RUNTIME_DIR/pvault.sock
  (fallback: /tmp/pvault.sock)

------------------------------------------------------------
Limitations
------------------------------------------------------------

- No synchronization across machines
- No GUI (CLI-only by design)
- No protection against same-user malware
- Secrets are accessible while daemon is unlocked

------------------------------------------------------------
Project Goals
------------------------------------------------------------

pvault is intended as:

- A systems programming project
- A security-focused learning exercise
- A demonstration of IPC, daemons, and cryptographic hygiene in C

It is not intended to replace mature password managers.
------------------------------------------------------------

## Commands

### Add an entry
pvault --add SERVICE

Prompts for:
- username (optional)
- password (press enter to auto-generate)
- link (optional)

If the service already exists, it is replaced.

### Find an entry
pvault --find SERVICE

Prints:
- service
- username
- password
- link

### Remove an entry
pvault --remove SERVICE

Deletes the entry for the given service.

### List entries
pvault --list
pvault --list all
pvault --list N

No argument: list up to 5 entries  
all: list every entry  
N: list the first N entries

### Dump decrypted vault
pvault --dump

Creates a plaintext dump of all entries in:

~/Downloads/pvault_dump_XXXXXX.txt

This file is decrypted and should be handled carefully.

------------------------------------------------------------

## Installation

### Build
gcc -std=c11 -Wall -Wextra -O2 \
  $(find . -name '*.c') \
  -o pvault -lsodium
