#ifndef _HIDGD_TPM_H
#define _HIDGD_TPM_H

#include "u2f.h"

/* tpm.c */
int tpm_get_public_point(uint32_t parent, U2F_EC_POINT *pub, uint8_t *handle);
int tpm_check_key(uint32_t parent, uint8_t len, uint8_t *key);
int tpm_sign(uint32_t parent, uint32_t counter, U2F_AUTHENTICATE_REQ *req,
	     uint8_t *ctr, uint8_t *sig);

/* crypto.c */
int crypto_fill_register_sig(uint32_t parent, U2F_REGISTER_REQ *req,
			     U2F_REGISTER_RESP *resp, uint8_t *sig, void *key);
void *crypto_load_key(const char *file);

#endif
