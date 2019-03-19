#ifndef _HIDGD_TPM_H
#define _HIDGD_TPM_H

#include "u2f.h"

void tpm_get_public_point(uint32_t handle, U2F_EC_POINT *pub);
int tpm_fill_register_sig(uint32_t parent, U2F_REGISTER_REQ *req,
			  U2F_REGISTER_RESP *resp, uint8_t *sig);

#endif
