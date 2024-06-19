// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#if OECRYPTO_OPENSSL_VER >= 3
#include <openenclave/bits/defs.h>
#include <openenclave/internal/crypto/init.h>
#include <openssl/core.h>

/* When the enclave does not opt into the SymCrypt provider at link time,
 * the following implementation (weak) will be picked by the linker.
 * Note that we have to put the function in a separated source file from
 * init.c to prevent the linker pulls in the symbol along with the
 * oe_crypto_initialize function. */
int _oe_scossl_provider_initialize(
    const OSSL_CORE_HANDLE* handle,
    const OSSL_DISPATCH* in,
    const OSSL_DISPATCH** out,
    void** provctx)
{
    return 0;
}
OE_WEAK_ALIAS(_oe_scossl_provider_initialize, OSSL_provider_init);
#endif
