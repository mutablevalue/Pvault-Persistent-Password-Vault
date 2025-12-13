#pragma once
#include <stddef.h>
#include <sys/types.h>
int ConnectToDaemon(void); // attempt connection daemon
int EnsureListener(void);  // after connection is made establish a listener
