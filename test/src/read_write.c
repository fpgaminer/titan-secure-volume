#include <string.h>
#include <minunit.h>
#include <titan-secure-volume/titan-secure-volume.h>
#include <titan-secure-volume/app.h>


void new_ramdisk (size_t len);


/* Performs a random mix of small and large writes to the disk, and then reads back
 * to make sure all the writes succeeded.
 */
START_TEST (test_read_write0)
{
	int err;
	uint8_t mac_key[TSV_MAC_KEY_SIZE];
	uint8_t encryption_key[TSV_ENCRYPTION_KEY_SIZE];
	int volume_len = 32 * 1024 * 1024;
	uint8_t *buf = malloc (1024 * 1024);
	uint8_t *real_copy = malloc (volume_len);
	uint8_t *result = malloc (volume_len);

	tsv_read_urandom (mac_key, sizeof (mac_key));
	tsv_read_urandom (encryption_key, sizeof (encryption_key));
	tsv_close ();

	new_ramdisk (volume_len * 3);
	mu_assert (!tsv_create (mac_key, encryption_key, 512, volume_len / 512), "tsv_create should succeed here.");
	mu_assert (!tsv_open (mac_key, encryption_key), "tsv_open should succeed here.");

	err = tsv_write (0, real_copy, volume_len);
	mu_assert (!err, "tsv_write should succeed at the beginning of read-write test.");

	for (int i = 0; i < 1024; ++i)
	{
		uint32_t len, offset;

		tsv_read_urandom (&len, sizeof (len));
		tsv_read_urandom (&offset, sizeof (offset));
		if (len & 0x80000000)
			len = len % (1024 * 1024);
		else
			len = len % (1024);

		tsv_read_urandom (buf, len);

		offset = offset % (volume_len - len);

		memmove (real_copy + offset, buf, len);

		err = tsv_write (offset, buf, len);
		mu_assert (!err, "tsv_write should succeed during random read-write test.");
	}

	/* Read back */
	err = tsv_read (result, 0, volume_len);
	mu_assert (!err, "tsv_read should succeed in read-write test.");

	mu_assert (!memcmp (result, real_copy, volume_len), "Readback during read-write test should give back same data written.");
}
END_TEST


char *test_read_write (void)
{
	mu_run_test (test_read_write0);

	return 0;
}
