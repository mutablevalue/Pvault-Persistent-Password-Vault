#include "helpers.h"

#include <stdlib.h>
#include <string.h>

int PromptUser(const char *PromptText, char *Buffer, size_t BufferSize) {
  fprintf(stderr, "%s: ", PromptText);
  if (!fgets(Buffer, (int)BufferSize, stdin))
    return -1;

  size_t Length = strlen(Buffer);
  if (Length && Buffer[Length - 1] == '\n')
    Buffer[Length - 1] = '\0';
  return 0;
}

char *DuplicateString(const char *Text) {
  if (!Text || !Text[0])
    return NULL;

  size_t Length = strlen(Text);
  char *Copy = malloc(Length + 1);
  if (!Copy)
    return NULL;

  memcpy(Copy, Text, Length + 1);
  return Copy;
}

void WriteU32LittleEndian(unsigned char *Destination, uint32_t Value) {
  Destination[0] = (unsigned char)(Value & 0xFF);
  Destination[1] = (unsigned char)((Value >> 8) & 0xFF);
  Destination[2] = (unsigned char)((Value >> 16) & 0xFF);
  Destination[3] = (unsigned char)((Value >> 24) & 0xFF);
}
// all reads/writes will simply just cast -> shift bytes take only the least
// signficant byte
int ReadU32LittleEndian(const unsigned char *Source, const unsigned char *End,
                        uint32_t *OutValue) {
  if (!Source || !OutValue || Source + 4 > End)
    return -1;

  *OutValue = (uint32_t)Source[0] | ((uint32_t)Source[1] << 8) |
              ((uint32_t)Source[2] << 16) | ((uint32_t)Source[3] << 24);
  return 0;
}

void WriteU64LittleEndian(unsigned char *Destination, uint64_t Value) {
  for (int Index = 0; Index < 8; Index++)
    Destination[Index] = (unsigned char)((Value >> (Index * 8)) & 0xFF);
}

int ReadU64LittleEndian(const unsigned char *Source, const unsigned char *End,
                        uint64_t *OutValue) {
  if (!Source || !OutValue || Source + 8 > End)
    return -1;

  uint64_t Result = 0;
  for (int Index = 0; Index < 8; Index++)
    Result |= ((uint64_t)Source[Index]) << (Index * 8);

  *OutValue = Result;
  return 0;
}

int WriteUint32ToFile(FILE *File, uint32_t Value) {
  unsigned char Bytes[4];
  WriteU32LittleEndian(Bytes, Value);
  return fwrite(Bytes, 1, 4, File) == 4 ? 0 : -1;
}

int ReadUint32FromFile(FILE *File, uint32_t *OutValue) {
  unsigned char Bytes[4];
  if (fread(Bytes, 1, 4, File) != 4)
    return -1;
  return ReadU32LittleEndian(Bytes, Bytes + 4, OutValue);
}

int WriteUint64ToFile(FILE *File, uint64_t Value) {
  unsigned char Bytes[8];
  WriteU64LittleEndian(Bytes, Value);
  return fwrite(Bytes, 1, 8, File) == 8 ? 0 : -1;
}

int ReadUint64FromFile(FILE *File, uint64_t *OutValue) {
  unsigned char Bytes[8];
  if (fread(Bytes, 1, 8, File) != 8)
    return -1;
  return ReadU64LittleEndian(Bytes, Bytes + 8, OutValue);
}
