#include <string.h>
#include <minunit.h>
#include <titan-secure-volume/titan-secure-volume.h>
#include <titan-secure-volume/app.h>


void new_ramdisk (size_t len);


START_TEST (test_read0)
{
	int err;
	uint8_t mac_key[TSV_MAC_KEY_SIZE];
	uint8_t encryption_key[TSV_ENCRYPTION_KEY_SIZE];
	uint8_t buf[1024];

	tsv_read_urandom (mac_key, sizeof (mac_key));
	tsv_read_urandom (encryption_key, sizeof (encryption_key));
	tsv_close ();

	new_ramdisk (5*512);
	mu_assert (!tsv_create (mac_key, encryption_key, 512, 1), "tsv_create should succeed in test_read.");

	err = tsv_read (buf, 0, 1);
	mu_assert (err, "tsv_read should fail if the volume isn't open.");

	mu_assert (!tsv_open (mac_key, encryption_key), "tsv_open should succeed.");

	err = tsv_read (buf, 512, 1);
	mu_assert (err, "tsv_read should fail if reading outside disk.");

	err = tsv_read (buf, 0, 513);
	mu_assert (err, "tsv_read should fail if reading outside disk.");

	err = tsv_read (buf, 0, 1);
	mu_assert (!err, "tsv_read should succeed if reading inside the disk.");
}
END_TEST


char *test_read (void)
{
	mu_run_test (test_read0);

	return 0;
}
