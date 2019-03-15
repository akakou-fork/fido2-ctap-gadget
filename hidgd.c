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

/*
 * The FIDO protocol has got to be one of the most screwed
 * up on the planet: All the HID frame messages are little endian
 * and all the U2F messages are big endian
 */
static void u2f_setbe(int val, uint8_t *buf)
{
	buf[0] = (val >> 8) & 0xff;
	buf[1] = val & 0xff;
}

static int u2f_getbe(uint8_t *buf)
{
	return (buf[0] << 8) + buf[1];
}

static void u2fhid_set_len(U2FHID_FRAME *frame, int len)
{
	frame->init.bcntl = len & 0xff;
	frame->init.bcnth = (len >> 8) & 0xff;
}

static int get_apdu(uint8_t **ptr)
{
	int len;

	if (**ptr == 0) {
		len = u2f_getbe(*ptr + 1);
		*ptr += 3;
	} else {
		len = *(*ptr)++;
	}

	return len;
}

static void process_error(uint32_t cid, int err)
{
	char buf[HID_RPT_SIZE];
	U2FHID_FRAME *reply = (U2FHID_FRAME *)buf;
	int count;

	memset(buf, 0, sizeof(buf));
	reply->cid = cid;
	reply->init.cmd = U2FHID_ERROR;
	reply->init.bcnth = 0;
	reply->init.bcntl = sizeof(reply) + 1;
	reply->init.data[0] = err;

	count = write(dev, buf, sizeof(buf));
	printf("wrote error frame %d\n", count);
}

static int get_payload(U2FHID_FRAME *frame, uint8_t buf[HID_MAX_PAYLOAD])
{
	int len = MSG_LEN(*frame);
	int count = sizeof(frame->init.data);
	int seq = 0;

	memcpy(buf, frame->init.data, count);

	printf("looking for packet of len %d\n", len);

	while (count < len) {
		int c = read(dev, frame, HID_RPT_SIZE);

		if (c != HID_RPT_SIZE) {
			fprintf(stderr, "Got short read of sequence packet %d != %d\n", c, HID_RPT_SIZE);
			process_error(frame->cid, ERR_INVALID_LEN);
			return -ERR_INVALID_LEN;
		}

		if (seq++ != frame->cont.seq) {
			fprintf(stderr, "Invalid sequence %d != %d\n", seq-1, frame->cont.seq);
			return -ERR_INVALID_SEQ;
		}
		memcpy(&buf[count], frame->cont.data, sizeof(frame->cont.data));
		count += sizeof(frame->cont.data);
	}
	return len;
}

static void send_payload(uint8_t ctap[HID_MAX_PAYLOAD], int len, uint32_t cid)
{
	uint8_t buf[HID_RPT_SIZE];
	U2FHID_FRAME *frame = (U2FHID_FRAME *)buf;
	int count;
	int seq = 0;

	/* response bytes at end */
	u2f_setbe(U2F_SW_NO_ERROR, &ctap[len]);
	/* account for response bytes */
	len += 2;

	frame->cid = cid;
	frame->init.cmd = U2FHID_MSG;
	u2fhid_set_len(frame, len);
	count = sizeof(frame->init.data);
	memcpy(frame->init.data, ctap, count);
	write(dev, buf, sizeof(buf));

	while (count < len) {
		frame->cid = cid;
		frame->cont.seq = seq++;
		memcpy(frame->cont.data, &ctap[count], sizeof(frame->cont.data));
		count += sizeof(frame->cont.data);
		write(dev, buf, sizeof(buf));
	}
}

static void process_version(uint32_t cid)
{
	uint8_t buf[HID_RPT_SIZE];
	U2FHID_FRAME *frame = (U2FHID_FRAME *)buf;
	static const char *repl = "U2F_V2";
	const int len = strlen(repl);

	memset(buf, 0, sizeof(buf));
	frame->cid = cid;
	frame->init.cmd = U2FHID_MSG;
	frame->init.bcnth = 0;
	frame->init.bcntl = len + 2; /* error at end */
	memcpy(frame->init.data, repl, len);
	u2f_setbe(U2F_SW_NO_ERROR, &frame->init.data[len]);
	write(dev, buf, sizeof(buf));
}

static void process_register(uint32_t cid, uint8_t ctap[HID_MAX_PAYLOAD])
{
	uint8_t buf[HID_MAX_PAYLOAD];
	U2F_REGISTER_REQ *req;
	U2F_REGISTER_RESP *resp = (U2F_REGISTER_RESP *)buf;
	uint8_t *ptr = &ctap[4];	/* point to APDU lengths */
	int len;

	len = get_apdu(&ptr);
	if (len != sizeof(U2F_REGISTER_REQ)) {
		fprintf(stderr, "Wrong REGISTER REQ len %d != %ld\n",
			len, sizeof(U2F_REGISTER_REQ));
		process_error(cid, ERR_INVALID_CMD);
		return;
	}
	len = get_apdu(&ptr);
	/*
	 * standard seems to require this but Mozilla doesn't transmit it
	if (len < sizeof(U2F_REGISTER_RESP)) {
		fprintf(stderr, "Wrong REGISTER RESP len %d < %ld\n",
			len, sizeof(U2F_REGISTER_RESP));
		process_error(cid, ERR_INVALID_CMD);
		return;
	}
	*/
	req = (U2F_REGISTER_REQ *)ptr;
	printf("chal[0] = %d, appId[0] = %d\n", req->chal[0], req->appId[0]);
	memset(buf, 0, sizeof(buf));
	resp->registerId = 0x05;
	resp->keyHandleLen = 240;
	const char *const str = "This is a key handle";
	strcpy((char *)resp->keyHandleCertSig, str);
	send_payload(buf, sizeof(U2F_REGISTER_RESP), cid);
}

static void process_msg(U2FHID_FRAME *frame)
{
	uint8_t ctap[HID_MAX_PAYLOAD];
	int len;
	int ins;

	uint32_t cid = frame->cid;

	len = get_payload(frame, ctap);
	if (len < 0) {
		process_error(frame->cid, -len);
		return;
	}
	ins = ctap[1];
	printf("Got CLA=0x%x, ins=0x%x\n", ctap[0], ins);

	if (ins == U2F_VERSION) {
		printf("U2F VERSION\n");
		process_version(cid);
	} else if (ins == U2F_REGISTER) {
		printf("U2F REGISTER\n");
		process_register(cid, ctap);
	} else {
		printf("Unrecognized command 0x%x\n", ins);
	}
}

static void process_init(U2FHID_FRAME *frame)
{
	char buf[HID_RPT_SIZE];
	U2FHID_FRAME *reply = (U2FHID_FRAME *)buf;
	U2FHID_INIT_REQ *req = (U2FHID_INIT_REQ *)frame->init.data;
	U2FHID_INIT_RESP *resp = (U2FHID_INIT_RESP *)reply->init.data;
	int count;

	if (MSG_LEN(*frame) != sizeof(U2FHID_INIT_REQ)) {
		fprintf(stderr, "INIT message wrong length %d != %ld\n",
			MSG_LEN(*frame),
			sizeof(U2FHID_INIT_REQ));
		process_error(frame->cid, ERR_INVALID_LEN);
		return;
	}
	if (frame->cid != CID_BROADCAST) {
		fprintf(stderr, "INIT message to wrong cid %x\n", frame->cid);
		process_error(frame->cid, ERR_INVALID_CMD);
		return;
	}
	memset(buf, 0, sizeof(buf));
	reply->cid = CID_BROADCAST;
	reply->init.cmd = U2FHID_INIT;
	reply->init.bcnth = 0;
	reply->init.bcntl = sizeof(*resp);
	printf("setting reply size to %ld\n", sizeof(*resp));
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
	} else if (frame->init.cmd == U2FHID_MSG){
		printf("Got MSG\n");
		process_msg(frame);
	} else {
		printf("Got unknown command 0x%x\n", FRAME_CMD(*frame));
		process_error(frame->cid, ERR_INVALID_CMD);
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
