#include <string.h>
#include <minunit.h>
#include <titan_secure_volume/titan_secure_volume.h>
#include <titan_secure_volume/bsp.h>


void new_ramdisk (size_t len);


START_TEST (test_write0)
{
	int err;
	uint8_t mac_key[TSV_MAC_KEY_SIZE];
	uint8_t encryption_key[TSV_ENCRYPTION_KEY_SIZE];
	uint8_t buf[1024] = {0};

	tsv_read_urandom (mac_key, sizeof (mac_key));
	tsv_read_urandom (encryption_key, sizeof (encryption_key));
	tsv_close ();

	new_ramdisk (5*512);
	mu_assert (!tsv_create (mac_key, encryption_key, 512, 1), "tsv_create should succeed in test_write.");

	err = tsv_write (0, buf, 1);
	mu_assert (err, "tsv_write should fail if the volume isn't open.");

	mu_assert (!tsv_open (mac_key, encryption_key), "tsv_open should succeed in test_write.");

	err = tsv_write (512, buf, 1);
	mu_assert (err, "tsv_write should fail if writing outside disk.");

	err = tsv_write (0, buf, 513);
	mu_assert (err, "tsv_write should fail if writing outside disk.");

	err = tsv_write (0, buf, 1);
	mu_assert (!err, "tsv_write should succeed if writing inside the disk.");
}
END_TEST


char *test_write (void)
{
	mu_run_test (test_write0);

	return 0;
}
