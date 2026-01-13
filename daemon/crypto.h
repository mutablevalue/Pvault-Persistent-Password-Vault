#pragma once

#include <stddef.h>
#include <stdint.h>

#include <sodium.h>
// encryption algo = XSalsa20
// Construction Algo = AEAD XSalsa20
// Auth Poly1305
typedef struct {
  unsigned char *Cipher;
  size_t CipherLength;
  unsigned char Nonce[crypto_secretbox_NONCEBYTES];
} EncEntry;

typedef struct {
  char *Service;
  char *Username;
  char *Password;
  char *Link;
} PlainEntry;

typedef struct {
  EncEntry *Entries;
  size_t Count;
  size_t Capacity;

  unsigned char MasterKey[crypto_secretbox_KEYBYTES];
  unsigned char Salt[crypto_pwhash_SALTBYTES];

  EncEntry Check; // if this is the first time setting up the vault
  int HasCheck;

  int HasMaster; // if they need to create a master password
  int Unlocked;  // master password accepted
} CryptoContext;

int PackEntry(const PlainEntry *Entry, unsigned char **OutBuffer,
              size_t *OutLength);

int UnpackEntry(const unsigned char *Buffer, size_t BufferLength,
                PlainEntry *OutEntry);
// compression / decompression
void CryptoInitContext(CryptoContext *Context);
void CryptoFreeContext(CryptoContext *Context);
// Starts up context window
int CryptoIsUnlocked(const CryptoContext *Context);
int CryptoHasMaster(const CryptoContext *Context);

int CryptoUnlockWithPassword(CryptoContext *Context, const char *Password);
int CryptoCreateMasterWithPassword(CryptoContext *Context,
                                   const char *Password);

int CryptoAddEntry(CryptoContext *Context, const char *Name);
int CryptoRemoveEntry(CryptoContext *Context, const char *Name);
int CryptoUpdateEntry(CryptoContext *Context, const char *EntryName,
                      const char *Field, const char *Value);
int CryptoFindEntryToSocket(CryptoContext *Context, const char *Name,
                            int SocketFd);
int CryptoListEntriesToSocket(CryptoContext *Context, const char *Arg,
                              int SocketFd);

int CryptoDumpEntriesDecrypted(CryptoContext *Context, char **OutPath);

int CryptoLoadVault(CryptoContext *Context);
int CryptoSaveVault(const CryptoContext *Context);
