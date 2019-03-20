/*
 * Crypto Code for hid gadget driver
 *
 * Copyright (C) 2019 James.Bottomley@HansenPartnership.com
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdio.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "u2f.h"
#include "hidgd.h"

void *crypto_load_key(const char *file)
{
	BIO *b = NULL;
        EVP_PKEY *pkey;

        b = BIO_new_file(file, "r");
        if (b == NULL) {
		ERR_print_errors_fp(stderr);
                return NULL;
        }

	pkey = PEM_read_bio_PrivateKey(b, NULL, PEM_def_callback, NULL);
        if (pkey == NULL)
		ERR_print_errors_fp(stderr);

        BIO_free(b);

        return pkey;
}

int crypto_fill_register_sig(uint32_t parent, U2F_REGISTER_REQ *req,
			     U2F_REGISTER_RESP *resp, uint8_t *sig,
			     void *key)
{
	EVP_MD_CTX *ctx;
	EVP_PKEY *pkey = key;
	uint8_t prefix[1];
	size_t len;

	/* conventional prefix containing zero byte */
	prefix[0] = 0x00;

	ctx = EVP_MD_CTX_new();
	if (!ctx)
		goto error;

	if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1)
		goto error;

	EVP_DigestSignUpdate(ctx, prefix, sizeof(prefix));
	EVP_DigestSignUpdate(ctx, req->appId, sizeof(req->appId));
	EVP_DigestSignUpdate(ctx, req->chal, sizeof(req->chal));
	EVP_DigestSignUpdate(ctx, resp->keyHandleCertSig, resp->keyHandleLen);
	EVP_DigestSignUpdate(ctx, &resp->pubKey, sizeof(resp->pubKey));

	if (EVP_DigestSignFinal(ctx, sig, &len) != 1)
		goto error;

	return len;
 error:
	ERR_print_errors_fp(stderr);
	return 0;
}
