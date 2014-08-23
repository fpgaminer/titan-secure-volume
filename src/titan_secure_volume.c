#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <titan_secure_volume/titan_secure_volume.h>
#include "basic_packing.h"
#include "util.h"
#include <titan_secure_volume/bsp.h>
#include "_ciphers.h"


#define member_size(type, member) sizeof(((type *)0)->member)

/* Size of internal buffers used for decrypting sectors, for example.  Consumed as global memory. */
#define BUFFER_SIZE 4096

#define TSV_HEADER_SIZE (8+2+32+4+4+14)

typedef struct __attribute__((__packed__))
{
	uint8_t magic[8];                 /* Magic Identifier ('TITANTSV') */
	uint8_t version[2];               /* Version (0x0100) */
	uint8_t ciphersuite[32];          /* Cipher Suite */
	uint8_t sector_size[4];
	uint8_t sector_count[4];
	uint8_t padding[14];
} PACKED_TSV_HEADER;


/* Assertions */
_Static_assert (sizeof (PACKED_TSV_HEADER) == TSV_HEADER_SIZE, "Size of PACKED_TSV_HEADER struct does not match expected size.");

_Static_assert ((TSV_HEADER_SIZE % ENCRYPTION_BLOCK_SIZE) == 0, "Header must be an integer multiple of encryption block size.");

_Static_assert ((TSV_HEADER_SIZE + MAC_TAG_SIZE) <= BUFFER_SIZE, "Header + MAC TAG must fit into BUFFER_SIZE.");


/* Global State */
static bool g_volume_open = false;
static uint64_t g_sector_offset = 0;
static uint32_t g_sector_size = 0;
static uint32_t g_sector_count = 0;
static uint64_t g_volume_size = 0;
static uint8_t g_mac_key[TSV_MAC_KEY_SIZE] = {0};
static uint8_t g_encryption_key[TSV_ENCRYPTION_KEY_SIZE] = {0};
static uint8_t g_buffer[BUFFER_SIZE] = {0};



static int sanity_check_parameters (uint32_t sector_size, uint32_t sector_count)
{
	(void)sector_count;

	// Sector Size must not be zero.
	if (sector_size == 0)
		return -1;

	// Sector Size must be multiple of encryption block size.
	if ((sector_size % ENCRYPTION_BLOCK_SIZE) != 0)
		return -1;

	// Header must fit in one Sector (to make things simple)
	if ((TSV_HEADER_SIZE + MAC_TAG_SIZE) > sector_size)
		return -1;

	// Sector must fit in buffer
	if (sector_size > sizeof (g_buffer))
		return -1;

	return 0;
}


int tsv_create (uint8_t mac_key[static TSV_MAC_KEY_SIZE], uint8_t encryption_key[static TSV_ENCRYPTION_KEY_SIZE], uint32_t sector_size, uint32_t sector_count)
{
	PACKED_TSV_HEADER *const header_buffer = (PACKED_TSV_HEADER *)g_buffer;
	uint64_t storage_offset = 0;

	// Sanity checks
	RtnOnError (sanity_check_parameters (sector_size, sector_count));

	// Build header
	memmove (header_buffer->magic, "TITANTSV", 8);
	pack_uint16_little (header_buffer->version, 0x0100);
	memmove (header_buffer->ciphersuite, "Threefish-512-XTS-HMAC-SHA-256\x00\x00", 32);
	pack_uint32_little (header_buffer->sector_size, sector_size);
	pack_uint32_little (header_buffer->sector_count, sector_count);
	tsv_read_urandom (header_buffer->padding, member_size (PACKED_TSV_HEADER, padding));

	// Encrypt
	_volume_encrypt (g_buffer, encryption_key, g_buffer, TSV_HEADER_SIZE, 0);

	// Then MAC
	_volume_mac (g_buffer+TSV_HEADER_SIZE, mac_key, g_buffer, TSV_HEADER_SIZE, 0);

	// Extra padding to reach sector boundary
	tsv_read_urandom (g_buffer+TSV_HEADER_SIZE+MAC_TAG_SIZE, sector_size - (TSV_HEADER_SIZE+MAC_TAG_SIZE));

	// Write header
	RtnOnError (tsv_physical_write (storage_offset, g_buffer, sector_size));
	storage_offset += sector_size;

	/* Get ready to write the sectors and mac table */
	uint64_t mac_table_size = (uint64_t)sector_count * (uint64_t)MAC_TAG_SIZE;
	uint64_t mac_table_remaining = roundup_uint64 (mac_table_size, sector_size);
	uint64_t mac_table_offset = sector_size;
	uint64_t data_offset = mac_table_offset + mac_table_size;

	/* Fill all the Sectors with random data. */
	for (uint32_t remaining = sector_count, sector_num = 0; remaining; --remaining, ++sector_num)
	{
		tsv_read_urandom (g_buffer, sector_size);

		_volume_encrypt (g_buffer, encryption_key, g_buffer, sector_size, sector_num + 1);

		RtnOnError (tsv_physical_write (data_offset, g_buffer, sector_size));
		data_offset += sector_size;

		_volume_mac (g_buffer, mac_key, g_buffer, sector_size, sector_num + 1);

		RtnOnError (tsv_physical_write (mac_table_offset, g_buffer, MAC_TAG_SIZE));
		mac_table_offset += MAC_TAG_SIZE;
		mac_table_remaining -= MAC_TAG_SIZE;
	}

	/* Pad the MAC table with random data. */
	while (mac_table_remaining)
	{
		uint32_t write_len = (uint32_t)MIN (mac_table_remaining, (uint64_t)sizeof (g_buffer));

		tsv_read_urandom (g_buffer, write_len);

		RtnOnError (tsv_physical_write (mac_table_offset, g_buffer, write_len));
		mac_table_offset += write_len;
		mac_table_remaining -= write_len;
	}


	return 0;
}


int tsv_open (uint8_t mac_key[static TSV_MAC_KEY_SIZE], uint8_t encryption_key[static TSV_ENCRYPTION_KEY_SIZE])
{
	PACKED_TSV_HEADER *const header_buffer = (PACKED_TSV_HEADER *)g_buffer;
	uint8_t calculated_mac[MAC_TAG_SIZE];

	// Close current volume
	if (g_volume_open)
		tsv_flush ();
	g_volume_open = false;

	// Read header
	RtnOnError (tsv_physical_read (g_buffer, 0, TSV_HEADER_SIZE + MAC_TAG_SIZE));
	
	// MAC
	_volume_mac (calculated_mac, mac_key, g_buffer, TSV_HEADER_SIZE, 0);
	if (secure_memcmp (calculated_mac, g_buffer + TSV_HEADER_SIZE, MAC_TAG_SIZE))
		return -1;

	// Decrypt
	_volume_decrypt (g_buffer, encryption_key, g_buffer, TSV_HEADER_SIZE, 0);

	// Verify fields
	if (memcmp (header_buffer->magic, "TITANTSV", 8))
		return -1;

	if (unpack_uint16_little (header_buffer->version) != 0x0100)
		return -1;

	/* We currently break spec and only support Threefish. */
	if (memcmp (header_buffer->ciphersuite, "Threefish-512-XTS-HMAC-SHA-256\x00\x00", 32))
		return -1;

	uint32_t sector_size = unpack_uint32_little (header_buffer->sector_size);
	uint32_t sector_count = unpack_uint32_little (header_buffer->sector_count);

	RtnOnError (sanity_check_parameters (sector_size, sector_count));

	/* Everything looks good, finish opening. */
	g_sector_size = sector_size;
	g_sector_count = sector_count;
	g_sector_offset = g_sector_size + roundup_uint64 (((uint64_t)sector_count) * ((uint64_t)MAC_TAG_SIZE), g_sector_size);
	g_volume_size = (uint64_t)g_sector_size * (uint64_t)g_sector_count;

	memmove (g_mac_key, mac_key, TSV_MAC_KEY_SIZE);
	memmove (g_encryption_key, encryption_key, TSV_ENCRYPTION_KEY_SIZE);

	g_volume_open = true;

	return 0;
}


static int _read_sector (void *dst, uint32_t sector_num)
{
	uint8_t mac[MAC_TAG_SIZE];
	uint8_t calculated_mac[MAC_TAG_SIZE];

	if (!g_volume_open || sector_num >= g_sector_count)
		return -1;

	/* Read sector */
	RtnOnError (tsv_physical_read (dst, g_sector_offset + (uint64_t)sector_num * (uint64_t)g_sector_size, g_sector_size));
	RtnOnError (tsv_physical_read (mac, g_sector_size + (uint64_t)sector_num * (uint64_t)MAC_TAG_SIZE, MAC_TAG_SIZE));

	/* Authenticate */
	_volume_mac (calculated_mac, g_mac_key, dst, g_sector_size, sector_num + 1);

	if (secure_memcmp (mac, calculated_mac, MAC_TAG_SIZE))
		return -1;

	/* Decrypt */
	_volume_decrypt (dst, g_encryption_key, dst, g_sector_size, sector_num + 1);

	return 0;
}


int tsv_read (void *dst, uint64_t offset, size_t len)
{
	if (!g_volume_open)
		return -1;

	/* Make sure read is within the volume boundaries. */
	if ((offset + len) < offset)    /* Overflow check */
		return -1;

	if (offset >= g_volume_size || (offset + len - 1) >= g_volume_size)
		return -1;

	uint32_t sector_offset = (uint32_t)(offset % g_sector_size);
	uint32_t sector_num = (uint32_t)(offset / g_sector_size);

	while (len)
	{
		uint32_t read_len = MIN (len, g_sector_size - sector_offset);

		/* Read sector */
		RtnOnError (_read_sector (g_buffer, sector_num));

		/* Copy to destination */
		memmove (dst, g_buffer+sector_offset, read_len);

		sector_offset = 0;
		dst = ((uint8_t *)dst) + read_len;
		len -= read_len;
		sector_num += 1;
	}

	return 0;
}


int tsv_write (uint64_t offset, void const *src, size_t len)
{
	uint8_t calculated_mac_tag[MAC_TAG_SIZE];

	if (!g_volume_open)
		return -1;

	/* Writes must be within the volume size */
	if ((offset + len) < offset)
		return -1;

	if (offset >= g_volume_size || (offset + len - 1) >= g_volume_size)
		return -1;

	uint32_t sector_offset = (uint32_t)(offset % g_sector_size);
	uint32_t sector_num = (uint32_t)(offset / g_sector_size);

	while (len)
	{
		/* How many bytes to write to the current sector */
		uint32_t write_len = MIN (len, g_sector_size - sector_offset);

		/* Read the sector if this is a partial write */
		if (write_len != g_sector_size)
		{
			RtnOnError (_read_sector (g_buffer, sector_num));
		}

		/* Modify */
		memmove (g_buffer+sector_offset, src, write_len);

		/* Encrypt */
		_volume_encrypt (g_buffer, g_encryption_key, g_buffer, g_sector_size, sector_num + 1);

		/* MAC */
		_volume_mac (calculated_mac_tag, g_mac_key, g_buffer, g_sector_size, sector_num + 1);

		/* Write */
		RtnOnError (tsv_physical_write (g_sector_offset + (uint64_t)sector_num * (uint64_t)g_sector_size, g_buffer, g_sector_size));
		RtnOnError (tsv_physical_write (g_sector_size + (uint64_t)sector_num * (uint64_t)MAC_TAG_SIZE, calculated_mac_tag, MAC_TAG_SIZE));

		sector_offset = 0;
		src = ((uint8_t const *)src) + write_len;
		len -= write_len;
		sector_num += 1;
	}

	return 0;
}


int tsv_flush (void)
{
	// Currently no caching, so no flushing necessary
	return 0;
}
