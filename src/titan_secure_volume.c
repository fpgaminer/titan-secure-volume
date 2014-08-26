#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "basic_packing.h"
#include "util.h"
#include <titan_secure_volume/bsp.h>
#include "_ciphers.h"
#include <titan_secure_volume/titan_secure_volume.h>


#define member_size(type, member) sizeof(((type *)0)->member)

/* Size of internal buffers used for decrypting sectors, for example.  Consumed as global memory. */
#define BUFFER_SIZE 4096

#define TSV_HEADER_SIZE (8+2+4+4+46)

typedef struct __attribute__((__packed__))
{
	uint8_t magic[8];                 /* Magic Identifier ('TITANTSV') */
	uint8_t version[2];               /* Version (0x0100) */
	uint8_t sector_size[4];
	uint8_t sector_count[4];
	uint8_t padding[46];
} PACKED_TSV_HEADER;


/* Assertions */
_Static_assert (sizeof (PACKED_TSV_HEADER) == TSV_HEADER_SIZE, "Size of PACKED_TSV_HEADER struct does not match expected size.");

_Static_assert ((TSV_HEADER_SIZE % ENCRYPTION_BLOCK_SIZE) == 0, "Header must be an integer multiple of encryption block size.");

_Static_assert ((TSV_HEADER_SIZE + MAC_TAG_SIZE) <= BUFFER_SIZE, "Header + MAC TAG must fit into BUFFER_SIZE.");


/* Global State */
static struct {
	bool open;
	uint32_t sector_size;
	uint32_t sector_count;

	uint64_t mac_table_size;
	uint64_t volume_size;     /* sector_count * sector_size */

	uint8_t mac_key[TSV_MAC_KEY_SIZE];
	uint8_t encryption_key[TSV_ENCRYPTION_KEY_SIZE];

	uint8_t buffer[BUFFER_SIZE];
	uint32_t corruption_count;
} g_volume = {0};



static int sanity_check_parameters (uint32_t sector_size, uint32_t sector_count)
{
	/* Sector count must be <= 0x7FFFFFFF */
	if (sector_count & 0x80000000)
		return -1;

	/* Sector Size cannot be 0 */
	if (sector_size == 0)
		return -1;

	// Sector Size must be multiple of encryption block size.
	if ((sector_size % ENCRYPTION_BLOCK_SIZE) != 0)
		return -1;

	// Header must fit in one Sector
	if ((TSV_HEADER_SIZE + MAC_TAG_SIZE) > sector_size)
		return -1;

	// Sector must fit in buffer
	if (sector_size > sizeof (g_volume.buffer))
		return -1;

	// Make sure entire volume will fit within 64-bit addressing
	uint64_t mac_table_size = roundup_uint64 ((uint64_t)sector_count * (uint64_t)MAC_TAG_SIZE, sector_size);
	uint64_t volume_size = (uint64_t)sector_size * (uint64_t)sector_count;

	if (mac_table_size + volume_size > (0x7FFFFFFFFFFFFFFFull - sector_size))
		return -1;

	return 0;
}


int tsv_create (uint8_t const mac_key[static TSV_MAC_KEY_SIZE], uint8_t const encryption_key[static TSV_ENCRYPTION_KEY_SIZE], uint32_t sector_size, uint32_t sector_count)
{
	int err;
	PACKED_TSV_HEADER *const header_buffer = (PACKED_TSV_HEADER *)g_volume.buffer;

	/* We consume some of the global state */
	if (g_volume.open)
		return -1;

	/* Sanity checks */
	RtnOnError (sanity_check_parameters (sector_size, sector_count));

	/* Build header */
	memmove (header_buffer->magic, "TITANTSV", 8);
	pack_uint16_little (header_buffer->version, 0x0100);
	pack_uint32_little (header_buffer->sector_size, sector_size);
	pack_uint32_little (header_buffer->sector_count, sector_count);
	tsv_read_urandom (header_buffer->padding, member_size (PACKED_TSV_HEADER, padding));

	// Encrypt
	_volume_encrypt (g_volume.buffer, encryption_key, g_volume.buffer, TSV_HEADER_SIZE, 0);

	// Then MAC
	_volume_mac (g_volume.buffer+TSV_HEADER_SIZE, mac_key, g_volume.buffer, TSV_HEADER_SIZE, 0);

	// Extra padding to reach sector boundary
	tsv_read_urandom (g_volume.buffer+TSV_HEADER_SIZE+MAC_TAG_SIZE, sector_size - (TSV_HEADER_SIZE+MAC_TAG_SIZE));

	/* Write header */
	RtnOnError (tsv_physical_write (0, g_volume.buffer, sector_size));

	/* Initialize all sectors to random data */
	g_volume.sector_size = sector_size;
	g_volume.sector_count = sector_count;
	g_volume.mac_table_size = roundup_uint64 (((uint64_t)sector_count) * ((uint64_t)MAC_TAG_SIZE), sector_size);
	g_volume.volume_size = (uint64_t)sector_size * (uint64_t)sector_count;
	memmove (g_volume.mac_key, mac_key, TSV_MAC_KEY_SIZE);
	memmove (g_volume.encryption_key, encryption_key, TSV_ENCRYPTION_KEY_SIZE);
	g_volume.open = true;

	/* First, fill MAC tables with noise */
	for (uint64_t remaining = g_volume.mac_table_size, offset = sector_size; remaining;)
	{
		uint32_t write_len = (uint32_t)MIN (remaining, (uint64_t)sizeof (g_volume.buffer));

		tsv_read_urandom (g_volume.buffer, write_len);
		if ((err = tsv_physical_write (offset, g_volume.buffer, write_len)))
		{
			tsv_close ();
			return err;
		}
		tsv_read_urandom (g_volume.buffer, write_len);
		if ((err = tsv_physical_write (offset + g_volume.mac_table_size + g_volume.volume_size, g_volume.buffer, write_len)))
		{
			tsv_close ();
			return err;
		}

		offset += write_len;
		remaining -= write_len;
	}

	/* Then write noise to all the sectors */
	for (uint32_t remaining = sector_count; remaining; --remaining)
	{
		uint64_t sector_num = remaining - 1;

		tsv_read_urandom (g_volume.buffer, g_volume.sector_size);

		if ((err = tsv_write (sector_num * g_volume.sector_size, g_volume.buffer, g_volume.sector_size)))
		{
			tsv_close ();
			return err;
		}
	}

	tsv_close ();
	return 0;
}


int tsv_open (uint8_t const mac_key[static TSV_MAC_KEY_SIZE], uint8_t const encryption_key[static TSV_ENCRYPTION_KEY_SIZE])
{
	PACKED_TSV_HEADER *const header_buffer = (PACKED_TSV_HEADER *)g_volume.buffer;
	uint8_t calculated_mac[MAC_TAG_SIZE];

	if (g_volume.open)
		return -1;

	// Read header
	RtnOnError (tsv_physical_read (g_volume.buffer, 0, TSV_HEADER_SIZE + MAC_TAG_SIZE));
	
	// MAC
	_volume_mac (calculated_mac, mac_key, g_volume.buffer, TSV_HEADER_SIZE, 0);
	if (secure_memcmp (calculated_mac, g_volume.buffer + TSV_HEADER_SIZE, MAC_TAG_SIZE))
		return -1;

	// Decrypt
	_volume_decrypt (g_volume.buffer, encryption_key, g_volume.buffer, TSV_HEADER_SIZE, 0);

	// Verify fields
	if (memcmp (header_buffer->magic, "TITANTSV", 8))
		return -1;

	if (unpack_uint16_little (header_buffer->version) != 0x0100)
		return -1;

	uint32_t sector_size = unpack_uint32_little (header_buffer->sector_size);
	uint32_t sector_count = unpack_uint32_little (header_buffer->sector_count);

	RtnOnError (sanity_check_parameters (sector_size, sector_count));

	/* Everything looks good, finish opening. */
	g_volume.sector_size = sector_size;
	g_volume.sector_count = sector_count;
	g_volume.mac_table_size = roundup_uint64 (((uint64_t)sector_count) * ((uint64_t)MAC_TAG_SIZE), sector_size);
	g_volume.volume_size = (uint64_t)sector_size * (uint64_t)sector_count;

	memmove (g_volume.mac_key, mac_key, TSV_MAC_KEY_SIZE);
	memmove (g_volume.encryption_key, encryption_key, TSV_ENCRYPTION_KEY_SIZE);

	g_volume.open = true;

	return 0;
}


static int _read_sector (void *dst, uint32_t sector_num)
{
	uint8_t mac[MAC_TAG_SIZE];
	uint8_t calculated_mac[MAC_TAG_SIZE];
	uint64_t offset = g_volume.sector_size;

	if (!g_volume.open || (sector_num & 0x7FFFFFFF) >= g_volume.sector_count)
		return -1;

	if (sector_num & 0x80000000)
		offset += g_volume.mac_table_size + g_volume.volume_size;

	/* Read sector */
	RtnOnError (tsv_physical_read (dst, offset + g_volume.mac_table_size + (uint64_t)(sector_num & 0x7FFFFFFF) * (uint64_t)g_volume.sector_size, g_volume.sector_size));
	RtnOnError (tsv_physical_read (mac, offset + (uint64_t)(sector_num & 0x7FFFFFFF) * (uint64_t)MAC_TAG_SIZE, MAC_TAG_SIZE));

	/* Authenticate */
	_volume_mac (calculated_mac, g_volume.mac_key, dst, g_volume.sector_size, sector_num + 1);

	if (secure_memcmp (mac, calculated_mac, MAC_TAG_SIZE))
		return -1;

	/* Decrypt */
	_volume_decrypt (dst, g_volume.encryption_key, dst, g_volume.sector_size, sector_num + 1);

	return 0;
}


static int _write_sector (uint32_t sector_num, void *src)
{
	uint8_t calculated_mac[MAC_TAG_SIZE];
	uint64_t offset = g_volume.sector_size;

	if (!g_volume.open || (sector_num & 0x7FFFFFFF) >= g_volume.sector_count)
		return -1;

	/* Encrypt */
	_volume_encrypt (src, g_volume.encryption_key, src, g_volume.sector_size, sector_num + 1);

	/* MAC */
	_volume_mac (calculated_mac, g_volume.mac_key, src, g_volume.sector_size, sector_num + 1);

	if (sector_num & 0x80000000)
		offset += g_volume.mac_table_size + g_volume.volume_size;
	sector_num &= 0x7FFFFFFF;

	/* Write */
	RtnOnError (tsv_physical_write (offset + g_volume.mac_table_size + (uint64_t)sector_num * (uint64_t)g_volume.sector_size, src, g_volume.sector_size));
	RtnOnError (tsv_physical_write (offset + (uint64_t)sector_num * (uint64_t)MAC_TAG_SIZE, calculated_mac, MAC_TAG_SIZE));

	return 0;
}


int tsv_read (void *dst, uint64_t offset, size_t len)
{
	if (!g_volume.open)
		return -1;

	if ((offset / g_volume.sector_size) >= g_volume.sector_count)
		return -1;

	uint32_t sector_num = (uint32_t)(offset / g_volume.sector_size);
	uint32_t sector_offset = offset % g_volume.sector_size;

	while (len)
	{
		uint32_t read_len = MIN (len, g_volume.sector_size - sector_offset);

		if (sector_num >= g_volume.sector_count)
			return -1;

		/* Read sector */
		if (_read_sector (g_volume.buffer, sector_num))
		{
			g_volume.corruption_count += 1;

			if (_read_sector (g_volume.buffer, sector_num | 0x80000000))
			{
				g_volume.corruption_count += 1;
				return -1;
			}
		}

		/* Copy to destination */
		memmove (dst, g_volume.buffer+sector_offset, read_len);

		sector_offset = 0;
		dst = ((uint8_t *)dst) + read_len;
		len -= read_len;
		sector_num += 1;
	}

	return 0;
}


int tsv_write (uint64_t offset, void const *src, size_t len)
{
	if (!g_volume.open)
		return -1;

	if ((offset / g_volume.sector_size) >= g_volume.sector_count)
		return -1;

	uint32_t sector_num = (uint32_t)(offset / g_volume.sector_size);
	uint32_t sector_offset = offset % g_volume.sector_size;

	while (len)
	{
		/* How many bytes to write to the current sector */
		uint32_t write_len = MIN (len, g_volume.sector_size - sector_offset);

		if (sector_num >= g_volume.sector_count)
			return -1;

		/* Read the sector if this is a partial write */
		/* During partial writes, we should overwrite damaged sectors first */
		uint32_t t_sector_num = sector_num;

		if (write_len != g_volume.sector_size)
		{
			if (_read_sector (g_volume.buffer, sector_num))
			{
				g_volume.corruption_count += 1;
				RtnOnError (_read_sector (g_volume.buffer, sector_num | 0x80000000));
			}
			else
			{
				/* If first replication is valid, overwrite the second first.
 				 * This way, if the second is invalid, we overwrite that first. */
				t_sector_num |= 0x80000000;
			}
		}

		/* Modify */
		memmove (g_volume.buffer+sector_offset, src, write_len);

		/* Write first sector */
		RtnOnError (_write_sector (t_sector_num, g_volume.buffer));

		/* Writer other sector */
		_volume_decrypt (g_volume.buffer, g_volume.encryption_key, g_volume.buffer, g_volume.sector_size, t_sector_num + 1);
		t_sector_num ^= 0x80000000;
		RtnOnError (_write_sector (t_sector_num, g_volume.buffer));

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


int tsv_close (void)
{
	if (g_volume.open)
		RtnOnError (tsv_flush ());

	memset (&g_volume, 0, sizeof (g_volume));

	return 0;
}
