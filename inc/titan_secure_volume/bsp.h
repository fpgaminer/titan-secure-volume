/*
 * These functions are platform specific and must be implemented by the application.
 */
#ifndef __TSV_BSP_H__
#define __TSV_BSP_H__

#include <stdlib.h>
#include <stdint.h>

void tsv_fatal_error (void);
void tsv_read_urandom (void *dst, size_t len);
int tsv_physical_read (void *dst, uint64_t offset, size_t len);
int tsv_physical_write (uint64_t offset, void const *src, size_t len);

#endif
