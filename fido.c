/*
 * Create the FIDO2 report descriptor for a HID gadget
 *
 * Copyright (C) 2019 James.Bottomley@HansenPartnership.com
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>

unsigned char report_desc[] = {
	0x06, 0xd0, 0xf1,	/* UsagePage(FIDO_USAGE_PAGE) */
	0x09, 0x01,		/* Usage(FIDO_USAGE_CTAPHID) */
	0xa1, 0x01,		/* Collection(Application) */
	0x09, 0x20,		/* Usage(FIDO_DATA_IN) */
	0x19, 0x00,		/* LogicalMin(0) */
	0x29, 0xff,		/* LogicalMax(FF) */
	0x75, 0x08,		/* ReportSize(8) */
	0x95, 0x40,		/* ReportCount(64) */
	0x81, 0x02,		/* Input(Data, Var, Abs) */
	0x09, 0x21,		/* Usage(FIDO_DATA_OUT) */
	0x19, 0x00,		/* LogicalMin(0) */
	0x29, 0xff,		/* LogicalMax(FF) */
	0x75, 0x08,		/* ReportSize(8) */
	0x95, 0x40,		/* ReportCount(64) */
	0x91, 0x02,		/* Output(Data, Var, Abs) */
	0xc0,			/* EndCollection */
};

int
main(int argc, char *argv[])
{
	int fd;

	printf("size is %d\n", sizeof(report_desc));
	if (argc != 2)
		exit(0);
	printf("writing file\n");
	fd = open(argv[1], O_CREAT|O_TRUNC|O_WRONLY);
	write (fd, report_desc, sizeof(report_desc));

	return 0;
}
