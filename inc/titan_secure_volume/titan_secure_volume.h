#ifndef __TITAN_SECURE_VOLUME_H__
#define __TITAN_SECURE_VOLUME_H__

#include <stdint.h>


#define TSV_MAC_KEY_SIZE 64
#define TSV_ENCRYPTION_KEY_SIZE 64


/* Titan Secure Volume API */

/* */
int tsv_create (uint8_t mac_key[static TSV_MAC_KEY_SIZE], uint8_t encryption_key[static TSV_ENCRYPTION_KEY_SIZE], uint32_t sector_size, uint32_t sector_count);

/* */
int tsv_open (uint8_t mac_key[static TSV_MAC_KEY_SIZE], uint8_t encryption_key[static TSV_ENCRYPTION_KEY_SIZE]);

/* */
int tsv_read (void *dst, uint64_t offset, size_t len);

/* */
int tsv_write (uint64_t offset, void const *src, size_t len);

/* */
int tsv_flush (void);


#endif
