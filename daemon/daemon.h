#pragma once
#include <string.h>
#include <unistd.h>
int EnsureDaemon(void);
void StartService(int Listener);
ssize_t ReadLine(int Socket, char *Buffer, size_t Size);
int WriteLine(int Socket, const char *Buffer);
