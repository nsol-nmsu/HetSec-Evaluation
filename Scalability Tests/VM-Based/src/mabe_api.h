#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mabe_ctx mabe_ctx;

/* Loads pairing from a.param and public params from public.json once. */
mabe_ctx* mabe_ctx_create(const char* param_path, const char* public_json_path);

/* Frees everything inside ctx. */
void mabe_ctx_free(mabe_ctx* ctx);

/* Decrypt: reads encrypt.json + userInfo.json and returns 32-byte key. */
int mabe_decrypt_key32_files(mabe_ctx* ctx,
                            const char* encrypt_json_path,
                            const char* user_json_path,
                            uint8_t out_key32[32]);

/* Encrypt: takes a 32-byte key, reads Auth1/2/3.json, produces encrypt.json bytes.
   On success: writes JSON to out_json (NUL terminated), sets *out_json_len, returns 0.
   If out buffer too small: sets *out_json_len to required size, returns -28 (ENOSPC).
*/
int mabe_encrypt_json_for_key32_files(mabe_ctx* ctx,
                                     const char* auth1_json_path,
                                     const char* auth2_json_path,
                                     const char* auth3_json_path,
                                     const uint8_t key32[32],
                                     char* out_json,
                                     size_t out_json_cap,
                                     size_t* out_json_len);

#ifdef __cplusplus
}
#endif