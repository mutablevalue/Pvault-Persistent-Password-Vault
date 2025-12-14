#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <sodium.h>

#include "crypto.h"
#include "helpers.h"

static const unsigned char CheckPlain[] = "PVAULT_CHECK_v1";

static int WriteAll(int Fd, const char *Buf, size_t Len) {
  while (Len > 0) {
    ssize_t W = write(Fd, Buf, Len);
    if (W < 0)
      return -1;
    Buf += (size_t)W;
    Len -= (size_t)W;
  }
  return 0;
}

static int WriteLineFd(int Fd, const char *Line) {
  if (!Line)
    return -1;
  size_t Len = strlen(Line);
  if (WriteAll(Fd, Line, Len) != 0)
    return -1;
  return WriteAll(Fd, "\n", 1);
}

static int WriteDataLineFd(int Fd, const char *Text) {
  char Line[2048];
  snprintf(Line, sizeof(Line), "DATA %s", Text ? Text : "");
  return WriteLineFd(Fd, Line);
}

static char *GetVaultPath(void) {
  const char *XdgDataHome = getenv("XDG_DATA_HOME");
  char DataHome[512];

  if (XdgDataHome && XdgDataHome[0]) {
    int Written = snprintf(DataHome, sizeof(DataHome), "%s", XdgDataHome);
    if (Written < 0 || (size_t)Written >= sizeof(DataHome))
      return NULL;
  } else {
    const char *Home = getenv("HOME");
    if (!Home || !Home[0])
      return NULL;

    int Written = snprintf(DataHome, sizeof(DataHome), "%s/.local/share", Home);
    if (Written < 0 || (size_t)Written >= sizeof(DataHome))
      return NULL;
  }

  char DirectoryPath[512];
  int Written =
      snprintf(DirectoryPath, sizeof(DirectoryPath), "%s/pvault", DataHome);
  if (Written < 0 || (size_t)Written >= sizeof(DirectoryPath))
    return NULL;

  if (mkdir(DirectoryPath, 0700) < 0 && errno != EEXIST)
    return NULL;

  char *VaultPath = malloc(512);
  if (!VaultPath)
    return NULL;

  Written = snprintf(VaultPath, 512, "%s/vault.dat", DirectoryPath);
  if (Written < 0 || Written >= 512) {
    free(VaultPath);
    return NULL;
  }

  return VaultPath;
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
  Context->Check.CipherLength = 0;
  memset(Context->Check.Nonce, 0, sizeof(Context->Check.Nonce));
  Context->HasCheck = 0;
}

static int EnsureCapacity(CryptoContext *Context, size_t Needed) {
  if (!Context)
    return -1;

  if (Needed <= Context->Capacity)
    return 0;

  size_t NewCapacity = Context->Capacity ? Context->Capacity : 8;
  while (NewCapacity < Needed) {
    if (NewCapacity > (SIZE_MAX / 2))
      return -1;
    NewCapacity *= 2;
  }

  if (NewCapacity > (SIZE_MAX / sizeof(EncEntry)))
    return -1;

  EncEntry *NewEntries =
      realloc(Context->Entries, NewCapacity * sizeof(EncEntry));
  if (!NewEntries)
    return -1;

  Context->Entries = NewEntries;
  Context->Capacity = NewCapacity;
  return 0;
}

static void FreePlainEntry(PlainEntry *Entry) {
  if (!Entry)
    return;

  if (Entry->Service) {
    sodium_memzero(Entry->Service, strlen(Entry->Service));
    free(Entry->Service);
  }
  if (Entry->Username) {
    sodium_memzero(Entry->Username, strlen(Entry->Username));
    free(Entry->Username);
  }
  if (Entry->Password) {
    sodium_memzero(Entry->Password, strlen(Entry->Password));
    free(Entry->Password);
  }
  if (Entry->Link) {
    sodium_memzero(Entry->Link, strlen(Entry->Link));
    free(Entry->Link);
  }

  memset(Entry, 0, sizeof(*Entry));
}

static int GeneratePassword(char *Buffer, size_t BufferSize,
                            size_t PasswordLength) {
  static const char Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                 "abcdefghijklmnopqrstuvwxyz"
                                 "0123456789"
                                 "!@#$%^&*_-+=?";
  size_t AlphabetLength = sizeof(Alphabet) - 1;

  if (!Buffer || BufferSize == 0)
    return -1;
  if (PasswordLength + 1 > BufferSize)
    return -1;

  for (size_t Index = 0; Index < PasswordLength; Index++) {
    uint32_t Choice = randombytes_uniform((uint32_t)AlphabetLength);
    Buffer[Index] = Alphabet[Choice];
  }

  Buffer[PasswordLength] = '\0';
  return 0;
}

static int MakeCheckBlock(CryptoContext *Context) {
  if (!Context)
    return -1;

  FreeCheck(Context);

  randombytes_buf(Context->Check.Nonce, sizeof(Context->Check.Nonce));

  Context->Check.CipherLength = sizeof(CheckPlain) + crypto_secretbox_MACBYTES;
  Context->Check.Cipher = malloc(Context->Check.CipherLength);
  if (!Context->Check.Cipher)
    return -1;

  if (crypto_secretbox_easy(Context->Check.Cipher, CheckPlain,
                            (unsigned long long)sizeof(CheckPlain),
                            Context->Check.Nonce, Context->MasterKey) != 0) {
    FreeCheck(Context);
    return -1;
  }

  Context->HasCheck = 1;
  return 0;
}

static int VerifyCheckBlock(CryptoContext *Context) {
  if (!Context || !Context->HasCheck || !Context->Check.Cipher)
    return -1;
  if (Context->Check.CipherLength < crypto_secretbox_MACBYTES)
    return -1;

  size_t PlainLength = Context->Check.CipherLength - crypto_secretbox_MACBYTES;
  unsigned char *Plain = malloc(PlainLength);
  if (!Plain)
    return -1;

  int IsValid = 0;

  if (crypto_secretbox_open_easy(
          Plain, Context->Check.Cipher,
          (unsigned long long)Context->Check.CipherLength, Context->Check.Nonce,
          Context->MasterKey) == 0) {
    if (PlainLength == sizeof(CheckPlain) &&
        memcmp(Plain, CheckPlain, sizeof(CheckPlain)) == 0) {
      IsValid = 1;
    }
  }

  sodium_memzero(Plain, PlainLength);
  free(Plain);
  return IsValid ? 0 : -1;
}

int PackEntry(const PlainEntry *Entry, unsigned char **OutBuffer,
              size_t *OutLength) {
  if (!Entry || !Entry->Service || !Entry->Password || !OutBuffer || !OutLength)
    return -1;

  uint32_t ServiceLength = (uint32_t)strlen(Entry->Service) + 1;
  uint32_t UsernameLength =
      Entry->Username ? (uint32_t)strlen(Entry->Username) + 1 : 0;
  uint32_t PasswordLength = (uint32_t)strlen(Entry->Password) + 1;
  uint32_t LinkLength = Entry->Link ? (uint32_t)strlen(Entry->Link) + 1 : 0;

  size_t TotalLength = 16;
  if (__builtin_add_overflow(TotalLength, (size_t)ServiceLength, &TotalLength))
    return -1;
  if (__builtin_add_overflow(TotalLength, (size_t)UsernameLength, &TotalLength))
    return -1;
  if (__builtin_add_overflow(TotalLength, (size_t)PasswordLength, &TotalLength))
    return -1;
  if (__builtin_add_overflow(TotalLength, (size_t)LinkLength, &TotalLength))
    return -1;

  unsigned char *Buffer = malloc(TotalLength);
  if (!Buffer)
    return -1;

  unsigned char *Cursor = Buffer;

  WriteU32LittleEndian(Cursor, ServiceLength);
  Cursor += 4;
  WriteU32LittleEndian(Cursor, UsernameLength);
  Cursor += 4;
  WriteU32LittleEndian(Cursor, PasswordLength);
  Cursor += 4;
  WriteU32LittleEndian(Cursor, LinkLength);
  Cursor += 4;

  memcpy(Cursor, Entry->Service, ServiceLength);
  Cursor += ServiceLength;

  if (UsernameLength) {
    memcpy(Cursor, Entry->Username, UsernameLength);
    Cursor += UsernameLength;
  }

  memcpy(Cursor, Entry->Password, PasswordLength);
  Cursor += PasswordLength;

  if (LinkLength) {
    memcpy(Cursor, Entry->Link, LinkLength);
    Cursor += LinkLength;
  }

  *OutBuffer = Buffer;
  *OutLength = TotalLength;
  return 0;
}

int UnpackEntry(const unsigned char *Buffer, size_t BufferLength,
                PlainEntry *OutEntry) {
  if (!Buffer || !OutEntry)
    return -1;

  memset(OutEntry, 0, sizeof(*OutEntry));

  const unsigned char *Cursor = Buffer;
  const unsigned char *End = Buffer + BufferLength;

  uint32_t ServiceLength = 0;
  uint32_t UsernameLength = 0;
  uint32_t PasswordLength = 0;
  uint32_t LinkLength = 0;

  if (ReadU32LittleEndian(Cursor, End, &ServiceLength) != 0)
    return -1;
  Cursor += 4;
  if (ReadU32LittleEndian(Cursor, End, &UsernameLength) != 0)
    return -1;
  Cursor += 4;
  if (ReadU32LittleEndian(Cursor, End, &PasswordLength) != 0)
    return -1;
  Cursor += 4;
  if (ReadU32LittleEndian(Cursor, End, &LinkLength) != 0)
    return -1;
  Cursor += 4;

  if (ServiceLength == 0 || PasswordLength == 0)
    return -1;

  size_t need = 0;
  if (__builtin_add_overflow(need, (size_t)ServiceLength, &need))
    return -1;
  if (__builtin_add_overflow(need, (size_t)UsernameLength, &need))
    return -1;
  if (__builtin_add_overflow(need, (size_t)PasswordLength, &need))
    return -1;
  if (__builtin_add_overflow(need, (size_t)LinkLength, &need))
    return -1;

  size_t remaining = (size_t)(End - Cursor);
  if (remaining < need)
    return -1;

  OutEntry->Service = malloc(ServiceLength);
  if (!OutEntry->Service)
    goto Fail;
  memcpy(OutEntry->Service, Cursor, ServiceLength);
  Cursor += ServiceLength;

  if (UsernameLength) {
    OutEntry->Username = malloc(UsernameLength);
    if (!OutEntry->Username)
      goto Fail;
    memcpy(OutEntry->Username, Cursor, UsernameLength);
    Cursor += UsernameLength;
  }

  OutEntry->Password = malloc(PasswordLength);
  if (!OutEntry->Password)
    goto Fail;
  memcpy(OutEntry->Password, Cursor, PasswordLength);
  Cursor += PasswordLength;

  if (LinkLength) {
    OutEntry->Link = malloc(LinkLength);
    if (!OutEntry->Link)
      goto Fail;
    memcpy(OutEntry->Link, Cursor, LinkLength);
  }

  return 0;

Fail:
  FreePlainEntry(OutEntry);
  return -1;
}

static int DecryptEntryToPlain(const CryptoContext *Context,
                               const EncEntry *EncryptedEntry,
                               unsigned char **OutPlain,
                               size_t *OutPlainLength) {
  if (!Context || !EncryptedEntry || !OutPlain || !OutPlainLength)
    return -1;
  if (!EncryptedEntry->Cipher ||
      EncryptedEntry->CipherLength < crypto_secretbox_MACBYTES)
    return -1;

  size_t PlainLength = EncryptedEntry->CipherLength - crypto_secretbox_MACBYTES;
  unsigned char *Plain = malloc(PlainLength);
  if (!Plain)
    return -1;

  if (crypto_secretbox_open_easy(
          Plain, EncryptedEntry->Cipher,
          (unsigned long long)EncryptedEntry->CipherLength,
          EncryptedEntry->Nonce, Context->MasterKey) != 0) {
    sodium_memzero(Plain, PlainLength);
    free(Plain);
    return -1;
  }

  *OutPlain = Plain;
  *OutPlainLength = PlainLength;
  return 0;
}

static int FindServiceIndex(CryptoContext *Context, const char *Name,
                            size_t *OutIndex) {
  if (!Context || !Name || !OutIndex)
    return -1;

  for (size_t Index = 0; Index < Context->Count; Index++) {
    EncEntry *EncryptedEntry = &Context->Entries[Index];

    unsigned char *Plain = NULL;
    size_t PlainLength = 0;
    if (DecryptEntryToPlain(Context, EncryptedEntry, &Plain, &PlainLength) != 0)
      continue;

    int MatchFound = 0;

    uint32_t ServiceLength = 0;
    const unsigned char *Cursor = Plain;
    const unsigned char *End = Plain + PlainLength;

    if (ReadU32LittleEndian(Cursor, End, &ServiceLength) == 0) {
      Cursor += 16;
      if (ServiceLength && Cursor + ServiceLength <= End) {
        const char *ServiceName = (const char *)Cursor;
        if (ServiceName && strcmp(ServiceName, Name) == 0)
          MatchFound = 1;
      }
    }

    sodium_memzero(Plain, PlainLength);
    free(Plain);

    if (MatchFound) {
      *OutIndex = Index;
      return 0;
    }
  }

  return -1;
}

static int ParseListArg(const char *Arg, size_t TotalCount, size_t *OutLimit) {
  if (!OutLimit)
    return -1;

  if (!Arg || !Arg[0]) {
    *OutLimit = (TotalCount < 5) ? TotalCount : 5;
    return 0;
  }

  if (strcmp(Arg, "all") == 0) {
    *OutLimit = TotalCount;
    return 0;
  }

  char *EndPointer = NULL;
  unsigned long ParsedValue = strtoul(Arg, &EndPointer, 10);
  if (!EndPointer || *EndPointer != '\0' || ParsedValue == 0)
    return -1;

  size_t Limit = (size_t)ParsedValue;
  if (Limit > TotalCount)
    Limit = TotalCount;

  *OutLimit = Limit;
  return 0;
}

void CryptoInitContext(CryptoContext *Context) {
  if (sodium_init() < 0)
    _exit(1);

  Context->Entries = NULL;
  Context->Count = 0;
  Context->Capacity = 0;

  Context->HasMaster = 0;
  Context->Unlocked = 0;

  Context->Check.Cipher = NULL;
  Context->Check.CipherLength = 0;
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

int CryptoHasMaster(const CryptoContext *Context) {
  return Context && Context->HasMaster;
}

int CryptoUnlockWithPassword(CryptoContext *Context, const char *Password) {
  if (!Context || !Password)
    return -1;
  if (!Context->HasMaster)
    return -1;

  if (crypto_pwhash(
          Context->MasterKey, sizeof(Context->MasterKey), Password,
          strlen(Password), Context->Salt, crypto_pwhash_OPSLIMIT_INTERACTIVE,
          crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
    return -1;
  }

  if (VerifyCheckBlock(Context) != 0) {
    sodium_memzero(Context->MasterKey, sizeof(Context->MasterKey));
    Context->Unlocked = 0;
    return -1;
  }

  Context->Unlocked = 1;
  return 0;
}

int CryptoCreateMasterWithPassword(CryptoContext *Context,
                                   const char *Password) {
  if (!Context || !Password)
    return -1;
  if (Context->HasMaster)
    return -1;

  randombytes_buf(Context->Salt, sizeof(Context->Salt));

  if (crypto_pwhash(
          Context->MasterKey, sizeof(Context->MasterKey), Password,
          strlen(Password), Context->Salt, crypto_pwhash_OPSLIMIT_INTERACTIVE,
          crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
    sodium_memzero(Context->MasterKey, sizeof(Context->MasterKey));
    return -1;
  }

  Context->HasMaster = 1;

  if (MakeCheckBlock(Context) != 0) {
    sodium_memzero(Context->MasterKey, sizeof(Context->MasterKey));
    Context->HasMaster = 0;
    return -1;
  }

  if (CryptoSaveVault(Context) != 0) {
    sodium_memzero(Context->MasterKey, sizeof(Context->MasterKey));
    Context->HasMaster = 0;
    FreeCheck(Context);
    return -1;
  }

  Context->Unlocked = 1;
  return 0;
}

int CryptoAddEntry(CryptoContext *Context, const char *Name) {
  if (!Context || !Name || !Name[0])
    return -1;
  if (!Context->Unlocked)
    return -1;

  PlainEntry Entry;
  memset(&Entry, 0, sizeof(Entry));

  Entry.Service = DuplicateString(Name);
  if (!Entry.Service)
    return -1;

  char UsernameBuffer[256];
  char PasswordBuffer[256];
  char LinkBuffer[512];

  UsernameBuffer[0] = '\0';
  PasswordBuffer[0] = '\0';
  LinkBuffer[0] = '\0';

  if (PromptUser("Username (optional)", UsernameBuffer,
                 sizeof(UsernameBuffer)) != 0) {
    FreePlainEntry(&Entry);
    return -1;
  }

  if (PromptUser("Password (enter to generate)", PasswordBuffer,
                 sizeof(PasswordBuffer)) != 0) {
    FreePlainEntry(&Entry);
    return -1;
  }

  if (PasswordBuffer[0] == '\0') {
    if (GeneratePassword(PasswordBuffer, sizeof(PasswordBuffer), 24) != 0) {
      FreePlainEntry(&Entry);
      return -1;
    }
    fprintf(stderr, "Generated password.\n");
  }

  if (PromptUser("Link (optional)", LinkBuffer, sizeof(LinkBuffer)) != 0) {
    sodium_memzero(PasswordBuffer, sizeof(PasswordBuffer));
    FreePlainEntry(&Entry);
    return -1;
  }

  if (UsernameBuffer[0])
    Entry.Username = DuplicateString(UsernameBuffer);

  Entry.Password = DuplicateString(PasswordBuffer);

  if (LinkBuffer[0])
    Entry.Link = DuplicateString(LinkBuffer);

  sodium_memzero(PasswordBuffer, sizeof(PasswordBuffer));

  if (!Entry.Password) {
    FreePlainEntry(&Entry);
    return -1;
  }

  unsigned char *Packed = NULL;
  size_t PackedLength = 0;

  if (PackEntry(&Entry, &Packed, &PackedLength) != 0) {
    FreePlainEntry(&Entry);
    return -1;
  }

  EncEntry EncryptedEntry;
  memset(&EncryptedEntry, 0, sizeof(EncryptedEntry));

  randombytes_buf(EncryptedEntry.Nonce, sizeof(EncryptedEntry.Nonce));

  EncryptedEntry.CipherLength = PackedLength + crypto_secretbox_MACBYTES;
  EncryptedEntry.Cipher = malloc(EncryptedEntry.CipherLength);
  if (!EncryptedEntry.Cipher) {
    sodium_memzero(Packed, PackedLength);
    free(Packed);
    FreePlainEntry(&Entry);
    return -1;
  }

  if (crypto_secretbox_easy(EncryptedEntry.Cipher, Packed,
                            (unsigned long long)PackedLength,
                            EncryptedEntry.Nonce, Context->MasterKey) != 0) {
    sodium_memzero(Packed, PackedLength);
    free(Packed);
    free(EncryptedEntry.Cipher);
    FreePlainEntry(&Entry);
    return -1;
  }

  sodium_memzero(Packed, PackedLength);
  free(Packed);
  FreePlainEntry(&Entry);

  size_t ExistingIndex = 0;
  if (FindServiceIndex(Context, Name, &ExistingIndex) == 0) {
    EncEntry OldEntry = Context->Entries[ExistingIndex];
    Context->Entries[ExistingIndex] = EncryptedEntry;

    if (CryptoSaveVault(Context) != 0) {
      free(Context->Entries[ExistingIndex].Cipher);
      Context->Entries[ExistingIndex] = OldEntry;
      return -1;
    }

    free(OldEntry.Cipher);
    return 0;
  }

  if (EnsureCapacity(Context, Context->Count + 1) != 0) {
    free(EncryptedEntry.Cipher);
    return -1;
  }

  size_t InsertIndex = Context->Count;
  Context->Entries[InsertIndex] = EncryptedEntry;
  Context->Count++;

  if (CryptoSaveVault(Context) != 0) {
    free(Context->Entries[InsertIndex].Cipher);
    Context->Entries[InsertIndex].Cipher = NULL;
    Context->Entries[InsertIndex].CipherLength = 0;
    memset(Context->Entries[InsertIndex].Nonce, 0,
           sizeof(Context->Entries[InsertIndex].Nonce));
    Context->Count--;
    return -1;
  }

  return 0;
}

int CryptoRemoveEntry(CryptoContext *Context, const char *Name) {
  if (!Context || !Name || !Name[0])
    return -1;
  if (!Context->Unlocked)
    return -1;

  size_t FoundIndex = 0;
  if (FindServiceIndex(Context, Name, &FoundIndex) != 0)
    return -1;

  free(Context->Entries[FoundIndex].Cipher);

  if (FoundIndex + 1 < Context->Count) {
    memmove(&Context->Entries[FoundIndex], &Context->Entries[FoundIndex + 1],
            (Context->Count - FoundIndex - 1) * sizeof(EncEntry));
  }

  Context->Count--;

  if (CryptoSaveVault(Context) != 0)
    return -1;

  return 0;
}

int CryptoFindEntryToSocket(CryptoContext *Context, const char *Name,
                            int SocketFd) {
  if (!Context || !Name || !Name[0])
    return -1;
  if (!Context->Unlocked)
    return -1;

  size_t FoundIndex = 0;
  if (FindServiceIndex(Context, Name, &FoundIndex) != 0)
    return -2; /* NOT_FOUND */

  EncEntry *EncryptedEntry = &Context->Entries[FoundIndex];

  unsigned char *Plain = NULL;
  size_t PlainLength = 0;
  if (DecryptEntryToPlain(Context, EncryptedEntry, &Plain, &PlainLength) != 0)
    return -1;

  int Result = -1;
  PlainEntry Decoded;

  if (UnpackEntry(Plain, PlainLength, &Decoded) == 0) {
    char Line[2048];

    snprintf(Line, sizeof(Line), "Service: %s",
             Decoded.Service ? Decoded.Service : "");
    WriteDataLineFd(SocketFd, Line);

    snprintf(Line, sizeof(Line), "Username: %s",
             Decoded.Username ? Decoded.Username : "");
    WriteDataLineFd(SocketFd, Line);

    snprintf(Line, sizeof(Line), "Password: %s",
             Decoded.Password ? Decoded.Password : "");
    WriteDataLineFd(SocketFd, Line);

    snprintf(Line, sizeof(Line), "Link: %s", Decoded.Link ? Decoded.Link : "");
    WriteDataLineFd(SocketFd, Line);

    FreePlainEntry(&Decoded);
    Result = 0;
  }

  sodium_memzero(Plain, PlainLength);
  free(Plain);
  return Result;
}

int CryptoListEntriesToSocket(CryptoContext *Context, const char *Arg,
                              int SocketFd) {
  if (!Context)
    return -1;
  if (!Context->Unlocked)
    return -1;

  size_t Limit = 0;
  if (ParseListArg(Arg, Context->Count, &Limit) != 0)
    return -1;

  for (size_t Index = 0; Index < Limit; Index++) {
    EncEntry *EncryptedEntry = &Context->Entries[Index];

    unsigned char *Plain = NULL;
    size_t PlainLength = 0;
    if (DecryptEntryToPlain(Context, EncryptedEntry, &Plain, &PlainLength) != 0)
      continue;

    uint32_t ServiceLength = 0;
    const unsigned char *Cursor = Plain;
    const unsigned char *End = Plain + PlainLength;

    if (ReadU32LittleEndian(Cursor, End, &ServiceLength) == 0) {
      Cursor += 16;
      if (ServiceLength && Cursor + ServiceLength <= End) {
        const char *ServiceName = (const char *)Cursor;
        if (ServiceName && ServiceName[0])
          WriteDataLineFd(SocketFd, ServiceName);
      }
    }

    sodium_memzero(Plain, PlainLength);
    free(Plain);
  }

  return 0;
}

static FILE *CreateRandomDumpFile(char **OutPath) {
  const char *Home = getenv("HOME");
  if (!Home || !Home[0])
    return NULL;

  char Template[512];
  int Written = snprintf(Template, sizeof(Template),
                         "%s/Downloads/pvault_dump_XXXXXX.txt", Home);
  if (Written < 0 || Written >= (int)sizeof(Template))
    return NULL;

  int FileDescriptor = mkstemps(Template, 4);
  if (FileDescriptor < 0)
    return NULL;

  FILE *OutFile = fdopen(FileDescriptor, "w");
  if (!OutFile) {
    close(FileDescriptor);
    unlink(Template);
    return NULL;
  }

  if (OutPath) {
    *OutPath = DuplicateString(Template);
    if (!*OutPath) {
      fclose(OutFile);
      unlink(Template);
      return NULL;
    }
  }

  return OutFile;
}

int CryptoDumpEntriesDecrypted(CryptoContext *Context, char **OutPath) {
  if (!Context || !OutPath)
    return -1;
  if (!Context->Unlocked)
    return -1;

  *OutPath = NULL;

  FILE *DumpFile = CreateRandomDumpFile(OutPath);
  if (!DumpFile)
    return -1;

  for (size_t i = 0; i < Context->Count; i++) {
    EncEntry *EncryptedEntry = &Context->Entries[i];

    unsigned char *Plain = NULL;
    size_t PlainLength = 0;
    if (DecryptEntryToPlain(Context, EncryptedEntry, &Plain, &PlainLength) != 0)
      continue;

    PlainEntry Decoded;
    if (UnpackEntry(Plain, PlainLength, &Decoded) == 0) {
      fprintf(DumpFile, "Service: %s\n",
              Decoded.Service ? Decoded.Service : "");
      fprintf(DumpFile, "Username: %s\n",
              Decoded.Username ? Decoded.Username : "");
      fprintf(DumpFile, "Password: %s\n",
              Decoded.Password ? Decoded.Password : "");
      fprintf(DumpFile, "Link: %s\n", Decoded.Link ? Decoded.Link : "");
      fprintf(DumpFile, "----\n");
      FreePlainEntry(&Decoded);
    }

    sodium_memzero(Plain, PlainLength);
    free(Plain);
  }

  fclose(DumpFile);
  return 0;
}

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
  if (ReadUint32FromFile(File, &Version) != 0 || Version != 2) {
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

  uint64_t CheckCipherLength64 = 0;
  if (ReadUint64FromFile(File, &CheckCipherLength64) != 0 ||
      CheckCipherLength64 == 0) {
    fclose(File);
    return -1;
  }

  Context->Check.CipherLength = (size_t)CheckCipherLength64;
  Context->Check.Cipher = malloc(Context->Check.CipherLength);
  if (!Context->Check.Cipher) {
    fclose(File);
    return -1;
  }

  if (fread(Context->Check.Cipher, 1, Context->Check.CipherLength, File) !=
      Context->Check.CipherLength) {
    fclose(File);
    FreeCheck(Context);
    return -1;
  }

  Context->HasCheck = 1;
  Context->HasMaster = 1;

  uint64_t EntryCount64 = 0;
  if (ReadUint64FromFile(File, &EntryCount64) != 0) {
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

    uint64_t CipherLength64 = 0;
    if (ReadUint64FromFile(File, &CipherLength64) != 0 || CipherLength64 == 0)
      goto Fail;

    Entry->CipherLength = (size_t)CipherLength64;
    Entry->Cipher = malloc(Entry->CipherLength);
    if (!Entry->Cipher)
      goto Fail;

    if (fread(Entry->Cipher, 1, Entry->CipherLength, File) !=
        Entry->CipherLength)
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

  if (!Context->HasMaster)
    return -1;

  if (!Context->HasCheck || !Context->Check.Cipher ||
      Context->Check.CipherLength == 0)
    return -1;

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

  if (WriteUint32ToFile(File, 2) != 0) {
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

  if (WriteUint64ToFile(File, (uint64_t)Context->Check.CipherLength) != 0) {
    fclose(File);
    return -1;
  }

  if (fwrite(Context->Check.Cipher, 1, Context->Check.CipherLength, File) !=
      Context->Check.CipherLength) {
    fclose(File);
    return -1;
  }

  if (WriteUint64ToFile(File, (uint64_t)Context->Count) != 0) {
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

    if (WriteUint64ToFile(File, (uint64_t)Entry->CipherLength) != 0) {
      fclose(File);
      return -1;
    }

    if (fwrite(Entry->Cipher, 1, Entry->CipherLength, File) !=
        Entry->CipherLength) {
      fclose(File);
      return -1;
    }
  }

  fclose(File);
  return 0;
}
