/*
 * TPM Code for hid gadget driver
 *
 * Copyright (C) 2019 James.Bottomley@HansenPartnership.com
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <tss.h>
#include <tssresponsecode.h>
#include <tsscryptoh.h>
#include <tssmarshal.h>

#include <openssl/ecdsa.h>

#include "hidgd.h"

static char *dir = NULL;
static TSS_CONTEXT *tssContext;

static void tpm2_error(TPM_RC rc, const char *reason)
{
	const char *msg, *submsg, *num;

	fprintf(stderr, "%s failed with %d\n", reason, rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	fprintf(stderr, "%s%s%s\n", msg, submsg, num);
}

#if 0
static void tpm2_rm_keyfile(TPM_HANDLE key)
{
        char keyfile[1024];

        snprintf(keyfile, sizeof(keyfile), "%s/h%08x.bin", dir, key);
        unlink(keyfile);
        snprintf(keyfile, sizeof(keyfile), "%s/hp%08x.bin", dir, key);
        unlink(keyfile);
}
#endif

static void tpm2_delete(void)
{
	if (rmdir(dir) < 0) {
		fprintf(stderr, "Unlinking %s", dir);
		perror(":");
	}
	TSS_Delete(tssContext);
	dir = NULL;
	tssContext = NULL;
}

static TPM_RC tpm2_create(void)
{
	char *prefix = getenv("XDG_RUNTIME_DIR");
	char *template;
	TPM_RC rc;

	if (!prefix)
		prefix = "/tmp";

	rc = TSS_Create(&tssContext);
	if (rc) {
		tpm2_error(rc, "TSS_Create");
		return rc;
	}

	if (!dir) {
		int len;

		len = snprintf(NULL, 0, "%s/tss2.XXXXXX", prefix);
		template = malloc(len + 1);
		snprintf(template, len + 1, "%s/tss2.XXXXXX", prefix);

		dir = mkdtemp(template);
	}

	printf("DIR IS %s\n", dir);
	rc = TSS_SetProperty(tssContext, TPM_DATA_DIR, dir);
	if (rc) {
		tpm2_error(rc, "TSS_SetProperty");
		return rc;
	}
	return TPM_RC_SUCCESS;
}

int tpm_get_public_point(uint32_t parent, U2F_EC_POINT *pub, uint8_t *handle)
{
	Create_In in;
	Create_Out out;
	TPM_RC rc;
	INT32 size;
	uint16_t len;
	TPMS_ECC_POINT *pt;

	rc = tpm2_create();
	if (rc)
		return 0;

	in.inPublic.publicArea.type = TPM_ALG_ECC;
	in.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
	in.inPublic.publicArea.authPolicy.t.size = 0;
	in.inPublic.publicArea.objectAttributes.val =
		TPMA_OBJECT_SIGN |
		TPMA_OBJECT_USERWITHAUTH |
		TPMA_OBJECT_NODA |
		TPMA_OBJECT_SENSITIVEDATAORIGIN;
	in.inPublic.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
        in.inPublic.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
        in.inPublic.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
        in.inPublic.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
        in.inPublic.publicArea.unique.ecc.x.t.size = 0;
        in.inPublic.publicArea.unique.ecc.y.t.size = 0;

	in.inSensitive.sensitive.userAuth.b.size = 0;
	in.inSensitive.sensitive.data.t.size = 0;
	in.parentHandle = parent;
	in.outsideInfo.t.size = 0;
	in.creationPCR.count = 0;

	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_Create,
			 TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0);
	tpm2_delete();
	if (rc) {
		tpm2_error(rc, "TPM2_Create");
		return 0;
	}

	size = 255;		/* max by U2F standard */
	len = 0;
	rc = TSS_TPM2B_PUBLIC_Marshal(&out.outPublic, &len, &handle, &size);
	if (rc) {
		tpm2_error(rc, "PUBLIC_Marshal");
		return 0;
	}
	rc = TSS_TPM2B_PRIVATE_Marshal(&out.outPrivate, &len, &handle, &size);
	if (rc) {
		tpm2_error(rc, "PRIVATE_Marshal");
		return 0;
	}

	pt = &out.outPublic.publicArea.unique.ecc;
	pub->pointFormat = U2F_POINT_UNCOMPRESSED;
	printf("PUBLIC POINTS  %d,%d\n", pt->x.t.size, pt->y.t.size);
	memcpy(pub->x, pt->x.t.buffer, pt->x.t.size);
	memcpy(pub->y, pt->y.t.buffer, pt->y.t.size);
	printf("DONE\n");

	return len;
}
