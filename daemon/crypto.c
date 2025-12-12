#include "crypto.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const unsigned char CheckPlain[] = "PVAULT_CHECK_v1";

static char *GetVaultPath(void) {
  const char *XdgDataHome = getenv("XDG_DATA_HOME");

  char DataHome[512];

  if (XdgDataHome && XdgDataHome[0]) {
    int Written = snprintf(DataHome, sizeof(DataHome), "%s", XdgDataHome);
    if (Written < 0 || (size_t)Written >= sizeof(DataHome)) {
      fprintf(stderr, "XDG_DATA_HOME too long\n");
      return NULL;
    }
  } else {
    const char *Home = getenv("HOME");
    if (!Home || !Home[0]) {
      fprintf(stderr, "Neither XDG_DATA_HOME nor HOME is set\n");
      return NULL;
    }

    int Written = snprintf(DataHome, sizeof(DataHome), "%s/.local/share", Home);
    if (Written < 0 || (size_t)Written >= sizeof(DataHome)) {
      fprintf(stderr, "HOME too long\n");
      return NULL;
    }
  }

  char DirPath[512];
  int Written = snprintf(DirPath, sizeof(DirPath), "%s/pvault", DataHome);
  if (Written < 0 || (size_t)Written >= sizeof(DirPath)) {
    fprintf(stderr, "Vault directory path too long\n");
    return NULL;
  }

  if (mkdir(DirPath, 0700) < 0 && errno != EEXIST) {
    perror("mkdir");
    return NULL;
  }

  char *VaultPath = malloc(512);
  if (!VaultPath)
    return NULL;

  Written = snprintf(VaultPath, 512, "%s/vault.dat", DirPath);
  if (Written < 0 || Written >= 512) {
    fprintf(stderr, "Vault path too long\n");
    free(VaultPath);
    return NULL;
  }

  return VaultPath;
}

static int WriteUint32(FILE *File, uint32_t Value) {
  unsigned char Bytes[4];
  Bytes[0] = (unsigned char)(Value & 0xFF);
  Bytes[1] = (unsigned char)((Value >> 8) & 0xFF);
  Bytes[2] = (unsigned char)((Value >> 16) & 0xFF);
  Bytes[3] = (unsigned char)((Value >> 24) & 0xFF);

  size_t Written = fwrite(Bytes, 1, 4, File);
  return (Written == 4) ? 0 : -1;
}

static int ReadUint32(FILE *File, uint32_t *OutValue) {
  unsigned char Bytes[4];
  size_t ReadCount = fread(Bytes, 1, 4, File);
  if (ReadCount != 4)
    return -1;

  *OutValue = (uint32_t)Bytes[0] | ((uint32_t)Bytes[1] << 8) |
              ((uint32_t)Bytes[2] << 16) | ((uint32_t)Bytes[3] << 24);
  return 0;
}

static int WriteUint64(FILE *File, uint64_t Value) {
  unsigned char Bytes[8];
  for (int Index = 0; Index < 8; Index++)
    Bytes[Index] = (unsigned char)((Value >> (Index * 8)) & 0xFF);

  size_t Written = fwrite(Bytes, 1, 8, File);
  return (Written == 8) ? 0 : -1;
}

static int ReadUint64(FILE *File, uint64_t *OutValue) {
  unsigned char Bytes[8];
  size_t ReadCount = fread(Bytes, 1, 8, File);
  if (ReadCount != 8)
    return -1;

  uint64_t Result = 0;
  for (int Index = 0; Index < 8; Index++)
    Result |= ((uint64_t)Bytes[Index]) << (Index * 8);

  *OutValue = Result;
  return 0;
}

static void FreeEntries(CryptoContext *Context) {
  if (!Context)
    return;

  for (size_t Index = 0; Index < Context->Count; Index++)
    free(Context->Entries[Index].Cipher);

  free(Context->Entries);

  Context->Entries = NULL;
  Context->Count = 0;
  Context->Capacity = 0;
}

static void FreeCheck(CryptoContext *Context) {
  if (!Context)
    return;

  free(Context->Check.Cipher);
  Context->Check.Cipher = NULL;
  Context->Check.CipherLen = 0;
  memset(Context->Check.Nonce, 0, sizeof(Context->Check.Nonce));
  Context->HasCheck = 0;
}

static int MakeCheckBlock(CryptoContext *Context) {
  if (!Context)
    return -1;

  FreeCheck(Context);

  randombytes_buf(Context->Check.Nonce, sizeof(Context->Check.Nonce));

  Context->Check.CipherLen = sizeof(CheckPlain) + crypto_secretbox_MACBYTES;
  Context->Check.Cipher = malloc(Context->Check.CipherLen);
  if (!Context->Check.Cipher)
    return -1;

  if (crypto_secretbox_easy(Context->Check.Cipher, CheckPlain,
                            sizeof(CheckPlain), Context->Check.Nonce,
                            Context->MasterKey) != 0) {
    FreeCheck(Context);
    return -1;
  }

  Context->HasCheck = 1;
  return 0;
}

static int VerifyCheckBlock(CryptoContext *Context) {
  if (!Context || !Context->HasCheck || !Context->Check.Cipher)
    return -1;
  if (Context->Check.CipherLen < crypto_secretbox_MACBYTES)
    return -1;

  size_t PlainLen = Context->Check.CipherLen - crypto_secretbox_MACBYTES;
  unsigned char *Plain = malloc(PlainLen);
  if (!Plain)
    return -1;

  int Ok = 0;
  if (crypto_secretbox_open_easy(Plain, Context->Check.Cipher,
                                 Context->Check.CipherLen, Context->Check.Nonce,
                                 Context->MasterKey) == 0) {
    if (PlainLen == sizeof(CheckPlain) &&
        memcmp(Plain, CheckPlain, sizeof(CheckPlain)) == 0) {
      Ok = 1;
    }
  }

  sodium_memzero(Plain, PlainLen);
  free(Plain);
  return Ok ? 0 : -1;
}

void CryptoInitContext(CryptoContext *Context) {
  if (sodium_init() < 0) {
    fprintf(stderr, "libsodium initialization failed\n");
    _exit(1);
  }

  Context->Entries = NULL;
  Context->Count = 0;
  Context->Capacity = 0;

  Context->HasMaster = 0;
  Context->Unlocked = 0;

  Context->Check.Cipher = NULL;
  Context->Check.CipherLen = 0;
  memset(Context->Check.Nonce, 0, sizeof(Context->Check.Nonce));
  Context->HasCheck = 0;

  sodium_memzero(Context->MasterKey, sizeof(Context->MasterKey));
  sodium_memzero(Context->Salt, sizeof(Context->Salt));
}

void CryptoFreeContext(CryptoContext *Context) {
  if (!Context)
    return;

  FreeEntries(Context);
  FreeCheck(Context);

  sodium_memzero(Context->MasterKey, sizeof(Context->MasterKey));
  sodium_memzero(Context->Salt, sizeof(Context->Salt));

  Context->HasMaster = 0;
  Context->Unlocked = 0;
}

int CryptoIsUnlocked(const CryptoContext *Context) {
  return Context && Context->Unlocked;
}

static int PromptUser(const char *Prompt, char *Buffer, size_t Size) {
  fprintf(stderr, "%s: ", Prompt);
  if (!fgets(Buffer, (int)Size, stdin))
    return -1;

  size_t Length = strlen(Buffer);
  if (Length && Buffer[Length - 1] == '\n')
    Buffer[Length - 1] = '\0';
  return 0;
}

int CryptoEnsureUnlocked(CryptoContext *Context) {
  if (!Context)
    return -1;

  if (Context->Unlocked)
    return 0;

  if (Context->HasMaster) {
    char Password[256];
    if (PromptUser("Enter Master Password", Password, sizeof(Password)) != 0)
      return -1;

    if (crypto_pwhash(Context->MasterKey, sizeof(Context->MasterKey), Password,
                      strlen(Password), Context->Salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
      fprintf(stderr, "Key derivation failed\n");
      sodium_memzero(Password, sizeof(Password));
      return -1;
    }

    sodium_memzero(Password, sizeof(Password));

    if (VerifyCheckBlock(Context) != 0) {
      fprintf(stderr, "Invalid master password\n");
      sodium_memzero(Context->MasterKey, sizeof(Context->MasterKey));
      Context->Unlocked = 0;
      return -1;
    }

    Context->Unlocked = 1;
    return 0;
  }

  char MasterPassword[256];

  for (;;) {
    char Password[256];
    char ConfirmPassword[256];

    if (PromptUser("Create master password", Password, sizeof(Password)) < 0)
      return -1;
    if (PromptUser("Confirm master password", ConfirmPassword,
                   sizeof(ConfirmPassword)) < 0)
      return -1;

    if (strcmp(Password, ConfirmPassword) != 0) {
      fprintf(stderr, "Passwords do not match\n");
      sodium_memzero(Password, sizeof(Password));
      sodium_memzero(ConfirmPassword, sizeof(ConfirmPassword));
      continue;
    }

    size_t Length = strlen(Password);
    if (Length >= sizeof(MasterPassword)) {
      fprintf(stderr, "Master password too long\n");
      sodium_memzero(Password, sizeof(Password));
      sodium_memzero(ConfirmPassword, sizeof(ConfirmPassword));
      return -1;
    }

    memcpy(MasterPassword, Password, Length + 1);
    sodium_memzero(Password, sizeof(Password));
    sodium_memzero(ConfirmPassword, sizeof(ConfirmPassword));
    break;
  }

  randombytes_buf(Context->Salt, sizeof(Context->Salt));

  if (crypto_pwhash(Context->MasterKey, sizeof(Context->MasterKey),
                    MasterPassword, strlen(MasterPassword), Context->Salt,
                    crypto_pwhash_OPSLIMIT_INTERACTIVE,
                    crypto_pwhash_MEMLIMIT_INTERACTIVE,
                    crypto_pwhash_ALG_DEFAULT) != 0) {
    fprintf(stderr, "Key derivation failed\n");
    sodium_memzero(MasterPassword, sizeof(MasterPassword));
    return -1;
  }

  Context->HasMaster = 1;

  if (MakeCheckBlock(Context) != 0) {
    fprintf(stderr, "Failed to create auth check block\n");
    sodium_memzero(MasterPassword, sizeof(MasterPassword));
    sodium_memzero(Context->MasterKey, sizeof(Context->MasterKey));
    Context->HasMaster = 0;
    return -1;
  }

  if (CryptoSaveVault(Context) != 0) {
    fprintf(stderr, "Failed to save new vault\n");
    sodium_memzero(MasterPassword, sizeof(MasterPassword));
    sodium_memzero(Context->MasterKey, sizeof(Context->MasterKey));
    Context->HasMaster = 0;
    FreeCheck(Context);
    return -1;
  }

  sodium_memzero(MasterPassword, sizeof(MasterPassword));
  Context->Unlocked = 1;
  return 0;
}

/* stubs for now */
int CryptoAddEntry(CryptoContext *Context, const char *Name) {
  if (!Context || !Name)
    return -1;
  if (CryptoEnsureUnlocked(Context) != 0)
    return -1;

  fprintf(stderr, "[crypto] ADD '%s' (stub only)\n", Name);
  return 0;
}

int CryptoRemoveEntry(CryptoContext *Context, const char *Name) {
  if (!Context || !Name)
    return -1;
  if (CryptoEnsureUnlocked(Context) != 0)
    return -1;

  fprintf(stderr, "[crypto] REMOVE '%s' (stub only)\n", Name);
  return 0;
}

int CryptoFindEntry(CryptoContext *Context, const char *Name) {
  if (!Context || !Name)
    return -1;
  if (CryptoEnsureUnlocked(Context) != 0)
    return -1;

  fprintf(stderr, "[crypto] FIND '%s' (stub only)\n", Name);
  return 0;
}

void CryptoListEntries(const CryptoContext *Context, const char *Prefix) {
  (void)Context;
  (void)Prefix;
  fprintf(stderr, "[crypto] LIST (stub)\n");
}

void CryptoDumpEntries(const CryptoContext *Context) {
  (void)Context;
  fprintf(stderr, "[crypto] DUMP (stub)\n");
}

/*
File format:
  4 bytes: "PVLT"
  u32: version (2)
  salt[crypto_pwhash_SALTBYTES]
  check_nonce[crypto_secretbox_NONCEBYTES]
  u64: check_cipher_len
  check_cipher[check_cipher_len]
  u64: entry_count
  repeated entry_count times:
    nonce[crypto_secretbox_NONCEBYTES]
    u64 cipher_len
    cipher[cipher_len]
*/

int CryptoLoadVault(CryptoContext *Context) {
  if (!Context)
    return -1;

  FreeEntries(Context);
  FreeCheck(Context);

  Context->HasMaster = 0;
  Context->Unlocked = 0;

  char *VaultPath = GetVaultPath();
  if (!VaultPath)
    return -1;

  FILE *File = fopen(VaultPath, "rb");
  free(VaultPath);

  if (!File) {
    Context->HasMaster = 0;
    return 0;
  }

  unsigned char Magic[4];
  if (fread(Magic, 1, 4, File) != 4) {
    fclose(File);
    return -1;
  }

  if (memcmp(Magic, "PVLT", 4) != 0) {
    fclose(File);
    return -1;
  }

  uint32_t Version = 0;
  if (ReadUint32(File, &Version) != 0 || Version != 2) {
    fclose(File);
    return -1;
  }

  if (fread(Context->Salt, 1, sizeof(Context->Salt), File) !=
      sizeof(Context->Salt)) {
    fclose(File);
    return -1;
  }

  if (fread(Context->Check.Nonce, 1, sizeof(Context->Check.Nonce), File) !=
      sizeof(Context->Check.Nonce)) {
    fclose(File);
    return -1;
  }

  uint64_t CheckLen64 = 0;
  if (ReadUint64(File, &CheckLen64) != 0 || CheckLen64 == 0) {
    fclose(File);
    return -1;
  }

  Context->Check.CipherLen = (size_t)CheckLen64;
  Context->Check.Cipher = malloc(Context->Check.CipherLen);
  if (!Context->Check.Cipher) {
    fclose(File);
    return -1;
  }

  if (fread(Context->Check.Cipher, 1, Context->Check.CipherLen, File) !=
      Context->Check.CipherLen) {
    fclose(File);
    FreeCheck(Context);
    return -1;
  }

  Context->HasCheck = 1;
  Context->HasMaster = 1;

  uint64_t EntryCount64 = 0;
  if (ReadUint64(File, &EntryCount64) != 0) {
    fclose(File);
    return -1;
  }

  size_t EntryCount = (size_t)EntryCount64;
  if (EntryCount == 0) {
    fclose(File);
    return 0;
  }

  EncEntry *Entries = calloc(EntryCount, sizeof(EncEntry));
  if (!Entries) {
    fclose(File);
    return -1;
  }

  for (size_t Index = 0; Index < EntryCount; Index++) {
    EncEntry *Entry = &Entries[Index];

    if (fread(Entry->Nonce, 1, sizeof(Entry->Nonce), File) !=
        sizeof(Entry->Nonce))
      goto Fail;

    uint64_t CipherLen64 = 0;
    if (ReadUint64(File, &CipherLen64) != 0 || CipherLen64 == 0)
      goto Fail;

    Entry->CipherLen = (size_t)CipherLen64;
    Entry->Cipher = malloc(Entry->CipherLen);
    if (!Entry->Cipher)
      goto Fail;

    if (fread(Entry->Cipher, 1, Entry->CipherLen, File) != Entry->CipherLen)
      goto Fail;
  }

  fclose(File);

  Context->Entries = Entries;
  Context->Count = EntryCount;
  Context->Capacity = EntryCount;
  return 0;

Fail:
  fclose(File);
  for (size_t Index = 0; Index < EntryCount; Index++)
    free(Entries[Index].Cipher);
  free(Entries);
  return -1;
}

int CryptoSaveVault(const CryptoContext *Context) {
  if (!Context)
    return -1;

  if (!Context->HasMaster) {
    fprintf(stderr, "Refusing to save: no master configured\n");
    return -1;
  }

  if (!Context->HasCheck || !Context->Check.Cipher ||
      Context->Check.CipherLen == 0) {
    fprintf(stderr, "Refusing to save: missing auth check block\n");
    return -1;
  }

  char *VaultPath = GetVaultPath();
  if (!VaultPath)
    return -1;

  FILE *File = fopen(VaultPath, "wb");
  free(VaultPath);

  if (!File)
    return -1;

  if (fwrite("PVLT", 1, 4, File) != 4) {
    fclose(File);
    return -1;
  }

  if (WriteUint32(File, 2) != 0) {
    fclose(File);
    return -1;
  }

  if (fwrite(Context->Salt, 1, sizeof(Context->Salt), File) !=
      sizeof(Context->Salt)) {
    fclose(File);
    return -1;
  }

  if (fwrite(Context->Check.Nonce, 1, sizeof(Context->Check.Nonce), File) !=
      sizeof(Context->Check.Nonce)) {
    fclose(File);
    return -1;
  }

  if (WriteUint64(File, (uint64_t)Context->Check.CipherLen) != 0) {
    fclose(File);
    return -1;
  }

  if (fwrite(Context->Check.Cipher, 1, Context->Check.CipherLen, File) !=
      Context->Check.CipherLen) {
    fclose(File);
    return -1;
  }

  if (WriteUint64(File, (uint64_t)Context->Count) != 0) {
    fclose(File);
    return -1;
  }

  for (size_t Index = 0; Index < Context->Count; Index++) {
    const EncEntry *Entry = &Context->Entries[Index];

    if (fwrite(Entry->Nonce, 1, sizeof(Entry->Nonce), File) !=
        sizeof(Entry->Nonce)) {
      fclose(File);
      return -1;
    }

    if (WriteUint64(File, (uint64_t)Entry->CipherLen) != 0) {
      fclose(File);
      return -1;
    }

    if (fwrite(Entry->Cipher, 1, Entry->CipherLen, File) != Entry->CipherLen) {
      fclose(File);
      return -1;
    }
  }

  fclose(File);
  return 0;
}
