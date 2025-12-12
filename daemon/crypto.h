#pragma once

#include "sodium.h"
#include <stddef.h>
#include <string.h>
typedef struct {
  unsigned char *Cipher; /* ciphertext buffer */
  size_t CipherLen;      /* includes MAC */
  unsigned char Nonce[crypto_secretbox_NONCEBYTES];
} EncEntry;

typedef struct {
  EncEntry *Entries;
  size_t Count;
  size_t Capacity;

  unsigned char
      MasterKey[crypto_secretbox_KEYBYTES]; /* derived from passphrase */
  unsigned char Salt[crypto_pwhash_SALTBYTES];

  EncEntry Check; // for password validation;
  int HasCheck;

  int HasMaster;
  int Unlocked;
} CryptoContext;

void CryptoInitContext(CryptoContext *Context);
void CryptoFreeContext(CryptoContext *Context);

int CryptoEnsureUnlocked(CryptoContext *Context);
int CryptoIsUnlocked(const CryptoContext *Context);

/* vault operations assume unlocked */
int CryptoAddEntry(CryptoContext *Context, const char *Name);
int CryptoRemoveEntry(CryptoContext *Context, const char *Name);
int CryptoFindEntry(CryptoContext *Context, const char *Name);
void CryptoListEntries(const CryptoContext *Context, const char *Prefix);
void CryptoDumpEntries(const CryptoContext *Context);
/* Save/load all EncEntry objects as one encrypted blob on disk. */
int CryptoLoadVault(CryptoContext *Context);
int CryptoSaveVault(const CryptoContext *Context);
