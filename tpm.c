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
#include <Unmarshal_fp.h>

#include <openssl/ecdsa.h>

#include "hidgd.h"

static char *dir = NULL;
static TSS_CONTEXT *tssContext;
static uint32_t count = 1000;

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

static TPM_HANDLE tpm2_create_primary(uint32_t hierarchy)
{
	TPM_RC rc;
	CreatePrimary_In in;
	CreatePrimary_Out out;

	/* SPS owner */
	in.primaryHandle = hierarchy;

	in.inSensitive.sensitive.userAuth.t.size = 0;

	/* no sensitive date for storage keys */
	in.inSensitive.sensitive.data.t.size = 0;
	/* no outside info */
	in.outsideInfo.t.size = 0;
	/* no PCR state */
	in.creationPCR.count = 0;

	/* public parameters for an ECC key  */
	in.inPublic.publicArea.type = TPM_ALG_ECC;
	in.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
	in.inPublic.publicArea.objectAttributes.val =
		TPMA_OBJECT_NODA |
		TPMA_OBJECT_SENSITIVEDATAORIGIN |
		TPMA_OBJECT_FIXEDPARENT |
		TPMA_OBJECT_FIXEDTPM |
		TPMA_OBJECT_USERWITHAUTH |
		TPMA_OBJECT_DECRYPT |
		TPMA_OBJECT_RESTRICTED;

	in.inPublic.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
	in.inPublic.publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
	in.inPublic.publicArea.parameters.eccDetail.symmetric.mode.aes = TPM_ALG_CFB;
	in.inPublic.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
	in.inPublic.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
	in.inPublic.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;

	in.inPublic.publicArea.unique.ecc.x.t.size = 0;
	in.inPublic.publicArea.unique.ecc.y.t.size = 0;
	in.inPublic.publicArea.authPolicy.t.size = 0;

	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_CreatePrimary,
			 TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0);

	if (rc) {
		tpm2_error(rc, "TSS_CreatePrimary");
		return 0;
	}

	return out.objectHandle;
}

static void tpm2_flush_handle(TPM_HANDLE h)
{
	FlushContext_In in;

	if (!h)
		return;

	in.flushHandle = h;
	TSS_Execute(tssContext, NULL,
		    (COMMAND_PARAMETERS *)&in,
		    NULL,
		    TPM_CC_FlushContext,
		    TPM_RH_NULL, NULL, 0);
}

static uint32_t tpm2_get_parent(uint32_t parent)
{
	if (parent == 0)
		/* choose default parent */
		parent = TPM_RH_OWNER;
	if ((parent & 0xff000000) == 0x40000000)
		parent = tpm2_create_primary(parent);

	return parent;
}

static void tpm2_put_parent(uint32_t parent)
{
	if ((parent & 0xff000000) == 0x80000000)
		tpm2_flush_handle(parent);
	tpm2_rm_keyfile(parent);
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

	parent = tpm2_get_parent(parent);

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
	tpm2_put_parent(parent);
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
	memcpy(pub->x, pt->x.t.buffer, pt->x.t.size);
	memcpy(pub->y, pt->y.t.buffer, pt->y.t.size);

	int i;
	for (i = 0; i < 65; i++) {
		printf("%02x:", *(&pub->pointFormat + i));
		if (i % 15 == 14)
			printf("\n");
	}
	printf("\n");

	return len;
}

static int tpm2_load_key(uint32_t parent, uint32_t len, uint8_t *key)
{
	Load_In in;
        Load_Out out;
        TPM_RC rc;
	const char *reason;

	in.parentHandle = parent;
	rc = TSS_TPM2B_PUBLIC_Unmarshalu(&in.inPublic, &key, &len, FALSE);
	if (rc) {
		reason = "PUBLIC_Unmarshal";
		goto error;
	}
	rc = TSS_TPM2B_PRIVATE_Unmarshalu(&in.inPrivate, &key, &len);
	if (rc) {
		reason = "PRIVATE_Unmarshal";
		goto error;
	}
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_Load,
			 TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0);
	if (rc) {
		reason= "TPM2_Load";
		goto error;
	}
	return out.objectHandle;
 error:
	tpm2_error(rc, reason);
	return 0;
}

int tpm_check_key(uint32_t parent, uint8_t len, uint8_t *key)
{
	TPM_HANDLE k;
	TPM_RC rc;
	int ret = 0;

	rc = tpm2_create();
	if (rc)
		return 0;

	parent = tpm2_get_parent(parent);

	k = tpm2_load_key(parent, len, key);
	if (!k)
		goto error;
	ret = 1;
	tpm2_flush_handle(k);
 error:
	tpm2_put_parent(parent);
	tpm2_delete();

	return ret;
}

int tpm_sign(uint32_t parent, U2F_AUTHENTICATE_REQ *req, uint8_t *ctr,
	     uint8_t *sig)
{
	TPMT_HA digest;
	TPM_RC rc;
	Sign_In in;
	Sign_Out out;
	ECDSA_SIG *osig;
	uint8_t presence[1];
	BIGNUM *r,*s;
	int len = 0;
	TPM_HANDLE k;
	int i;

	rc = tpm2_create();
	if (rc)
		return 0;

	parent = tpm2_get_parent(parent);

	k = tpm2_load_key(parent, req->keyHandleLen, req->keyHandle);
	tpm2_put_parent(parent);

	if (!k)
		goto error;

	presence[0] = 1;
	count++;
	printf("COUNTER: %d\n", count);
	for (i = 0; i < U2F_CTR_SIZE; i++) {
		ctr[i] = (count>>((U2F_CTR_SIZE - i - 1)*8)) & 0xff;
		printf("ctr[%d]=%d\n", i, ctr[i]);
	}
	printf("sizeof presence = %ld\n", sizeof(req->appId));

	digest.hashAlg = TPM_ALG_SHA256;
	TSS_Hash_Generate(&digest,
			  sizeof(req->appId), req->appId,
			  sizeof(presence), presence,
			  U2F_CTR_SIZE, ctr,
			  sizeof(req->chal), req->chal,
			  0, NULL);
	in.inScheme.details.ecdsa.hashAlg = digest.hashAlg;
	in.keyHandle = k;
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
        }
	tpm2_flush_handle(k);
 error:
	tpm2_delete();

	if (rc == TPM_RC_SUCCESS) {
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
	}
	printf("Sig of len %d\n", len);
	return len;
}
