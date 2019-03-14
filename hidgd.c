/*
 * Hid gadget driver daemon for FIDO2
 *
 * Copyright (C) 2019 James.Bottomley@HansenPartnership.com
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */


#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "u2f.h"
#include "u2f_hid.h"

static int dev;

static void process_error(U2FHID_FRAME *frame, int err)
{
	char buf[HID_RPT_SIZE];
	U2FHID_FRAME *reply = (U2FHID_FRAME *)buf;
	int count;

	memset(buf, 0, sizeof(buf));
	reply->cid = frame->cid;
	reply->init.cmd = U2FHID_ERROR;
	reply->init.bcnth = 0;
	reply->init.bcntl = sizeof(reply) + 1;
	reply->init.data[0] = err;

	count = write(dev, buf, sizeof(buf));
	printf("wrote error frame %d\n", count);
}

static void process_init(U2FHID_FRAME *frame)
{
	char buf[HID_RPT_SIZE];
	U2FHID_FRAME *reply = (U2FHID_FRAME *)buf;
	U2FHID_INIT_REQ *req = (U2FHID_INIT_REQ *)frame->init.data;
	U2FHID_INIT_RESP *resp = (U2FHID_INIT_RESP *)reply->init.data;
	int count;

	if (MSG_LEN(*frame) != sizeof(U2FHID_INIT_REQ)) {
		fprintf(stderr, "INIT message wrong length %d != %d\n",
			MSG_LEN(*frame),
			sizeof(U2FHID_INIT_REQ));
		process_error(frame, ERR_INVALID_LEN);
		return;
	}
	if (frame->cid != CID_BROADCAST) {
		fprintf(stderr, "INIT message to wrong cid %x\n", frame->cid);
		process_error(frame, ERR_INVALID_CMD);
		return;
	}
	memset(buf, 0, sizeof(buf));
	reply->cid = CID_BROADCAST;
	reply->init.cmd = U2FHID_INIT;
	reply->init.bcnth = 0;
	reply->init.bcntl = 17;
	printf("setting reply size to %d\n", sizeof(*resp));
	memcpy(resp->nonce, req->nonce, sizeof(req->nonce));
	resp->cid = 1;
	resp->versionInterface = U2FHID_IF_VERSION;

	count = write(dev, buf, sizeof(buf));
	printf("written %d bytes\n", count);
}

static void command_loop(void)
{
	int count;
	uint8_t buf[HID_RPT_SIZE];
	U2FHID_FRAME *frame = (U2FHID_FRAME *)buf;

	count = read(dev, buf, sizeof(buf));
	printf("received %d bytes\n", count);
	if (frame->init.cmd == U2FHID_INIT) {
		printf("Got INIT\n");
		process_init(frame);
	} else {
		printf("Got unknown command 0x%x\n", FRAME_CMD(*frame));
		process_error(frame, ERR_INVALID_CMD);
	}
}

int main(int argc, const char *argv[])
{
	if (argc != 2) {
		fprintf(stderr, "need hidg device\n");
		exit(1);
	}

	dev = open(argv[1], O_RDWR);
	if (dev < 0) {
		perror("Failed to open HIDG");
		exit(1);
	}

	for (;;) {
		command_loop();
	}
}
