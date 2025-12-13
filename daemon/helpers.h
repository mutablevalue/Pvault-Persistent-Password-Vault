#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

int PromptUser(const char *PromptText, char *Buffer, size_t BufferSize);

char *DuplicateString(const char *Text);

void WriteU32LittleEndian(unsigned char *Destination, uint32_t Value);
int ReadU32LittleEndian(const unsigned char *Source, const unsigned char *End,
                        uint32_t *OutValue);

void WriteU64LittleEndian(unsigned char *Destination, uint64_t Value);
int ReadU64LittleEndian(const unsigned char *Source, const unsigned char *End,
                        uint64_t *OutValue);

int WriteUint32ToFile(FILE *File, uint32_t Value);
int ReadUint32FromFile(FILE *File, uint32_t *OutValue);

int WriteUint64ToFile(FILE *File, uint64_t Value);
int ReadUint64FromFile(FILE *File, uint64_t *OutValue);
