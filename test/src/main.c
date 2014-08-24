#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include "minunit.h"
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <titan_secure_volume/titan_secure_volume.h>
#include <titan_secure_volume/bsp.h>

int tests_run = 0;

char *test_create (void);
char *test_open (void);
char *test_read (void);
char *test_write (void);
char *test_read_write (void);
char *test_corruption (void);


/* TSV BSP */
uint8_t *g_ramdisk = NULL;
size_t g_ramdisk_len = 0;

void tsv_fatal_error (void)
{
	fprintf (stderr, "ERROR: TSV_FATAL_ERROR\n");
	exit (-1);
}


void tsv_read_urandom (void *dst, size_t len)
{
	int fd = open ("/dev/urandom", O_RDONLY);

	if (fd == -1)
		tsv_fatal_error ();
	
	while (len)
	{
		ssize_t bytes = read (fd, dst, len);

		if (bytes < 0)
			tsv_fatal_error ();

		dst = ((uint8_t *)dst) + bytes;
		len -= (uint32_t)bytes;
	}

	close (fd);
}


int tsv_physical_read (void *dst, uint64_t offset, size_t len)
{
	if (!g_ramdisk)
		return -1;

	if (!len)
		return 0;

	if (offset >= g_ramdisk_len || (g_ramdisk_len - offset) < len)
		return -1;

	memmove (dst, g_ramdisk + offset, len);

	return 0;
}


int tsv_physical_write (uint64_t offset, void const *src, size_t len)
{
	if (!g_ramdisk)
		return -1;

	if (!len)
		return 0;

	if (offset >= g_ramdisk_len || (g_ramdisk_len - offset) < len)
		return -1;

	memmove (g_ramdisk + offset, src, len);

	return 0;
}


void new_ramdisk (size_t len)
{
	free (g_ramdisk);
	g_ramdisk = malloc (len);
	g_ramdisk_len = len;

	memset (g_ramdisk, 0, len);
}


static char *all_tests ()
{
	char *msg;

	if ((msg = test_create ())) return msg;
	if ((msg = test_open ())) return msg;
	if ((msg = test_read ())) return msg;
	if ((msg = test_write ())) return msg;
	if ((msg = test_read_write ())) return msg;
	if ((msg = test_corruption ())) return msg;
	
	return 0;
}


int main (void)
{
	char *result = all_tests ();
	
	if (result != 0)
		printf ("%s\n", result);
	else
		printf ("ALL TESTS PASSED\n");
	printf ("Tests run: %d\n", tests_run);
	
	return result != 0;
}
