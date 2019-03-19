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

#include <openssl/ecdsa.h>

#include "hidgd-tpm.h"

static char *dir = NULL;
static TSS_CONTEXT *tssContext;

static void tpm2_error(TPM_RC rc, const char *reason)
{
	const char *msg, *submsg, *num;

	fprintf(stderr, "%s failed with %d\n", reason, rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	fprintf(stderr, "%s%s%s\n", msg, submsg, num);
}

static void tpm2_rm_keyfile(TPM_HANDLE key)
{
        char keyfile[1024];

        snprintf(keyfile, sizeof(keyfile), "%s/h%08x.bin", dir, key);
        unlink(keyfile);
        snprintf(keyfile, sizeof(keyfile), "%s/hp%08x.bin", dir, key);
        unlink(keyfile);
}

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

void tpm_get_public_point(uint32_t handle, U2F_EC_POINT *pub)
{
	ReadPublic_In in;
	ReadPublic_Out out;
	TPM_RC rc;
	TPMS_ECC_POINT *pt;

	rc = tpm2_create();
	if (rc)
		return;

	in.objectHandle = handle;

	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_ReadPublic,
			 TPM_RH_NULL, NULL, 0);
	if (rc) {
		tpm2_error(rc, "TPM2_ReadPublic");
		return;
	}
	pt = &out.outPublic.publicArea.unique.ecc;
	pub->pointFormat = U2F_POINT_UNCOMPRESSED;
	printf("PUBLIC POINTS  %d,%d\n", pt->x.t.size, pt->y.t.size);
	memcpy(pub->x, pt->x.t.buffer, pt->x.t.size);
	memcpy(pub->y, pt->y.t.buffer, pt->y.t.size);
	printf("DONE\n");
}

int tpm_fill_register_sig(uint32_t parent, U2F_REGISTER_REQ *req,
			  U2F_REGISTER_RESP *resp, uint8_t *sig)
{
	TPMT_HA digest;
	TPM_RC rc;
	Sign_In in;
	Sign_Out out;
	uint8_t prefix[1];
	ECDSA_SIG *osig;
	BIGNUM *r,*s;
	int len;

	/* conventional prefix containing zero byte */
	prefix[0] = 0x00;

	digest.hashAlg = TPM_ALG_SHA256;

	TSS_Hash_Generate(&digest,
			  sizeof(prefix), prefix,
			  sizeof(req->appId), req->appId,
			  sizeof(req->chal), req->chal,
			  resp->keyHandleLen, resp->keyHandleCertSig,
			  sizeof(resp->pubKey), &resp->pubKey,
			  0, NULL);

	in.inScheme.details.ecdsa.hashAlg = digest.hashAlg;
	in.keyHandle = parent;
	in.inScheme.scheme = TPM_ALG_ECDSA;
	in.digest.t.size = TSS_GetDigestSize(digest.hashAlg);
	memcpy(in.digest.t.buffer, digest.digest.tssmax, in.digest.t.size);
	in.validation.tag = TPM_ST_HASHCHECK;
	in.validation.hierarchy = TPM_RH_NULL;
	in.validation.digest.t.size = 0;

	rc = TSS_Execute(tssContext,
                         (RESPONSE_PARAMETERS *)&out,
                         (COMMAND_PARAMETERS *)&in,
                         NULL,
                         TPM_CC_Sign,
			 TPM_RS_PW, NULL, 0,
                         TPM_RH_NULL, NULL, 0);
        if (rc) {
                tpm2_error(rc, "TPM2_Sign");
		return 0;
        }

	osig = ECDSA_SIG_new();
	r = BN_bin2bn(out.signature.signature.ecdsa.signatureR.t.buffer,
                      out.signature.signature.ecdsa.signatureR.t.size,
                      NULL);
        s = BN_bin2bn(out.signature.signature.ecdsa.signatureS.t.buffer,
                      out.signature.signature.ecdsa.signatureS.t.size,
                      NULL);
	ECDSA_SIG_set0(osig, r, s);
	len = i2d_ECDSA_SIG(osig, &sig);
	ECDSA_SIG_free(osig);

	tpm2_rm_keyfile(parent);
	tpm2_delete();

	return len;
}
