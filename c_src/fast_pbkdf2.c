/*
 * fast-pbkdf2 - Optimal PBKDF2-HMAC calculation
 * Written in 2015 by Joseph Birr-Pixton <jpixton@gmail.com>
 * Rewritten in 2025 by Nelson Vides <nelson.vides@erlang-solutions.com>
 *
 * To the extent possible under law, the author(s) have dedicated all
 * copyright and related and neighboring rights to this software to the
 * public domain worldwide. This software is distributed without any
 * warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication
 * along with this software. If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include "erl_nif.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#if defined(__GNUC__)
#include <sys/types.h>
#endif
#include <openssl/evp.h>
#include <openssl/sha.h>

// announce a timeslice of 5 percent when indicated
#define SLICE 20
#define TIMESLICE_PERCENTAGE 5

#define XSTRINGIFY(s) STRINGIFY(s)
#define STRINGIFY(s) #s

#define HMAC_CTX_ROUND(_name) HMAC_##_name##_ctx_round               // C struct
#define HMAC_CTX_ROUND_RES(_name) res_HMAC_##_name##_ctx_round       // Erlang Resource definition
#define HMAC_CTX_ROUND_NAME(_name) XSTRINGIFY(HMAC_CTX_ROUND(_name)) // Erlang atom-name

#define MD_NAME(_name) md_##_name
#define HMAC_INIT(_name) HMAC_##_name##_init
#define CLEANUP(_name) cleanup_rount_st_##_name // C struct

#define PBKDF2_F_MD(_name) pbkdf2_f_md##_name
#define PBKDF2_F(_name) pbkdf2_f_##_name
#define PBKDF2(_name) pbkdf2_##_name

typedef struct {
    ERL_NIF_TERM atom_sha;
    ERL_NIF_TERM atom_sha224;
    ERL_NIF_TERM atom_sha256;
    ERL_NIF_TERM atom_sha384;
    ERL_NIF_TERM atom_sha512;
    ERL_NIF_TERM atom_sha3_224;
    ERL_NIF_TERM atom_sha3_256;
    ERL_NIF_TERM atom_sha3_384;
    ERL_NIF_TERM atom_sha3_512;
    EVP_MD *MD_NAME(sha1);
    EVP_MD *MD_NAME(sha224);
    EVP_MD *MD_NAME(sha256);
    EVP_MD *MD_NAME(sha384);
    EVP_MD *MD_NAME(sha512);
    EVP_MD *MD_NAME(sha3_224);
    EVP_MD *MD_NAME(sha3_256);
    EVP_MD *MD_NAME(sha3_384);
    EVP_MD *MD_NAME(sha3_512);
    ErlNifResourceType *HMAC_CTX_ROUND_RES(sha1);
    ErlNifResourceType *HMAC_CTX_ROUND_RES(sha224);
    ErlNifResourceType *HMAC_CTX_ROUND_RES(sha256);
    ErlNifResourceType *HMAC_CTX_ROUND_RES(sha384);
    ErlNifResourceType *HMAC_CTX_ROUND_RES(sha512);
    ErlNifResourceType *HMAC_CTX_ROUND_RES(sha3_224);
    ErlNifResourceType *HMAC_CTX_ROUND_RES(sha3_256);
    ErlNifResourceType *HMAC_CTX_ROUND_RES(sha3_384);
    ErlNifResourceType *HMAC_CTX_ROUND_RES(sha3_512);
} pbkdf2_st;

static inline void write32_be(uint32_t n, uint8_t out[4]) {
#if defined(__GNUC__) && __GNUC__ >= 4 && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    *(uint32_t *)(out) = __builtin_bswap32(n);
#else
    out[0] = (n >> 24) & 0xff;
    out[1] = (n >> 16) & 0xff;
    out[2] = (n >> 8) & 0xff;
    out[3] = n & 0xff;
#endif
}

/* Prepare block (of blocksz bytes) to contain md padding denoting a msg-size
 * message (in bytes).  block has a prefix of used bytes.
 * Message length is expressed in 32 bits (so suitable for sha1, sha256, sha512). */
static inline void md_pad(uint8_t *block, size_t blocksz, size_t used, size_t msg) {
    memset(block + used, 0, blocksz - used - 4);
    block[used] = 0x80;
    block += blocksz - 4;
    write32_be((uint32_t)(msg * 8), block);
}

ERL_NIF_TERM mk_error(ErlNifEnv *env, const char *error_msg) {
    return enif_make_tuple2(env, enif_make_atom(env, "error"), enif_make_atom(env, error_msg));
}

typedef struct {
    EVP_MD_CTX *inner;
    EVP_MD_CTX *outer;
} HMAC_md_ctx;

/* This macro expands to decls for the whole implementation for a given
 * hash function.  Arguments are:
 *
 * _name like 'sha1', added to symbol names                         (e.g. sha256)
 * _blocksz block size, in bytes                                    (e.g. SHA256_CBLOCK)
 * _hashsz digest output, in bytes                                  (e.g. SHA256_DIGEST_LENGTH)
 * _iters_per_slot, the number of iterations per 5% of a timeslice  (e.g. 200)
 *
 * This macro generates the following functions:
 * - HMAC_CTX_ROUND(_name) - C struct to store the state of the iterations
 * - CLEANUP(_name): for example cleanup_round_st_sha256
 * - HMAC_INIT(_name) - C function to initialize the HMAC_CTX_ROUND(_name)
 * - PBKDF2_F_MD(_name) - Erlang function to iterate over the HMAC_CTX_ROUND(_name)
 * - PBKDF2_F(_name) - C function to iterate over the HMAC_CTX_ROUND(_name)
 *   and call PBKDF2_F_MD(_name)
 * - PBKDF2(_name) - Erlang function to call PBKDF2_F(_name)
 */
#define DECL_PBKDF2(_name, _blocksz, _hashsz, _iters_per_slot)                                     \
                                                                                                   \
    typedef struct {                                                                               \
        HMAC_md_ctx startctx;     /* Cache the `2` part of the `2+2i` optimisation */              \
        HMAC_md_ctx ctx;          /* Carry the `2i` of the algorithm */                            \
        uint8_t result[_hashsz];  /* Carry the XOR of each iteration and then the final output */  \
        uint8_t Ublock[_blocksz]; /* Carry the intermediate hashing of every HMAC on every iter */ \
        uint32_t iterations;      /* Carry the number of iterations left */                        \
    } HMAC_CTX_ROUND(_name);                                                                       \
                                                                                                   \
    /* Free the EVP_MD_CTX and nif resource allocated previously, if any */                        \
    static void CLEANUP(_name)(HMAC_CTX_ROUND(_name) *const restrict round_st) {                   \
        if (round_st->ctx.inner)                                                                   \
            EVP_MD_CTX_free(round_st->ctx.inner);                                                  \
        if (round_st->ctx.outer)                                                                   \
            EVP_MD_CTX_free(round_st->ctx.outer);                                                  \
        if (round_st->startctx.inner)                                                              \
            EVP_MD_CTX_free(round_st->startctx.inner);                                             \
        if (round_st->startctx.outer)                                                              \
            EVP_MD_CTX_free(round_st->startctx.outer);                                             \
        enif_release_resource(round_st);                                                           \
    }                                                                                              \
                                                                                                   \
    /* Initialise the startctx parts (the `2` in the `2+2i` optimisation) */                       \
    /* - If the key is longer than the block size, it is hashed first.*/                           \
    /* - The key is padded to the block size if necessary.*/                                       \
    /* - The inner and outer contexts are initialized with the padded key.*/                       \
    static inline int HMAC_INIT(_name)(HMAC_CTX_ROUND(_name) *restrict round_st,                   \
                                       const EVP_MD *restrict type, const uint8_t *restrict key,   \
                                       size_t nkey) {                                              \
        /* Prepare key: */                                                                         \
        uint8_t k[_blocksz];                                                                       \
                                                                                                   \
        /* Shorten long keys */                                                                    \
        if (nkey > _blocksz) {                                                                     \
            round_st->startctx.inner = EVP_MD_CTX_new();                                           \
            if (!round_st->startctx.inner) {                                                       \
                return 1;                                                                          \
            }                                                                                      \
            if (!EVP_DigestInit_ex2(round_st->startctx.inner, type, NULL) ||                       \
                !EVP_DigestUpdate(round_st->startctx.inner, key, nkey) ||                          \
                !EVP_DigestFinal_ex(round_st->startctx.inner, k, NULL)) {                          \
                return 1;                                                                          \
            }                                                                                      \
            EVP_MD_CTX_free(round_st->startctx.inner);                                             \
            round_st->startctx.inner = NULL;                                                       \
            key = k;                                                                               \
            nkey = _hashsz;                                                                        \
        }                                                                                          \
                                                                                                   \
        /* Standard doesn't cover case where blocksz < hashsz */                                   \
        assert(nkey <= _blocksz);                                                                  \
                                                                                                   \
        /* Right zero-pad short keys */                                                            \
        if (k != key)                                                                              \
            memcpy(k, key, nkey);                                                                  \
        if (_blocksz > nkey)                                                                       \
            memset(k + nkey, 0, _blocksz - nkey);                                                  \
                                                                                                   \
        /* Start inner hash computation */                                                         \
        uint8_t blk_inner[_blocksz];                                                               \
        uint8_t blk_outer[_blocksz];                                                               \
                                                                                                   \
        for (uint_fast8_t i = 0; i < _blocksz; i++) {                                              \
            blk_inner[i] = 0x36 ^ k[i];                                                            \
            blk_outer[i] = 0x5c ^ k[i];                                                            \
        }                                                                                          \
                                                                                                   \
        round_st->startctx.inner = EVP_MD_CTX_new();                                               \
        if (!round_st->startctx.inner ||                                                           \
            !EVP_DigestInit_ex2(round_st->startctx.inner, type, NULL) ||                           \
            !EVP_DigestUpdate(round_st->startctx.inner, blk_inner, sizeof blk_inner))              \
            return 1;                                                                              \
                                                                                                   \
        /* And outer */                                                                            \
        round_st->startctx.outer = EVP_MD_CTX_new();                                               \
        if (!round_st->startctx.outer ||                                                           \
            !EVP_DigestInit_ex2(round_st->startctx.outer, type, NULL) ||                           \
            !EVP_DigestUpdate(round_st->startctx.outer, blk_outer, sizeof blk_outer))              \
            return 1;                                                                              \
                                                                                                   \
        return 0;                                                                                  \
    }                                                                                              \
                                                                                                   \
    /* Run the actual iterations, possibly yielding the NIF or finally returning the result */     \
    /* - It iterates over the number of iterations, updating the context and XORing the results */ \
    /* - If the iterations exceed a certain threshold, it schedules the function to run again */   \
    /* - The final result is copied to the output buffer and returned */                           \
    ERL_NIF_TERM PBKDF2_F_MD(_name)(ErlNifEnv * env, const int argc, const ERL_NIF_TERM argv[]) {  \
        const pbkdf2_st *const mod_st = enif_priv_data(env);                                       \
        HMAC_CTX_ROUND(_name) *const restrict round_st;                                            \
        if (!enif_get_resource(env, argv[0], mod_st->HMAC_CTX_ROUND_RES(_name),                    \
                               (void *)(&round_st))) {                                             \
            return enif_make_badarg(env);                                                          \
        }                                                                                          \
                                                                                                   \
        while (1) {                                                                                \
            for (uint32_t i = 0; i < _iters_per_slot && i < round_st->iterations; ++i) {           \
                /* Complete inner hash with previous U */                                          \
                if (!EVP_MD_CTX_copy_ex(round_st->ctx.inner, round_st->startctx.inner) ||          \
                    !EVP_DigestUpdate(round_st->ctx.inner, round_st->Ublock, _hashsz) ||           \
                    !EVP_DigestFinal_ex(round_st->ctx.inner, round_st->Ublock, NULL)) {            \
                    goto error;                                                                    \
                }                                                                                  \
                                                                                                   \
                /* Complete outer hash with inner output */                                        \
                if (!EVP_MD_CTX_copy_ex(round_st->ctx.outer, round_st->startctx.outer) ||          \
                    !EVP_DigestUpdate(round_st->ctx.outer, round_st->Ublock, _hashsz) ||           \
                    !EVP_DigestFinal_ex(round_st->ctx.outer, round_st->Ublock, NULL)) {            \
                    goto error;                                                                    \
                }                                                                                  \
                                                                                                   \
                /* XOR the outer hash into the result */                                           \
                for (uint_fast8_t j = 0; j < _hashsz; ++j) {                                       \
                    round_st->result[j] ^= round_st->Ublock[j];                                    \
                }                                                                                  \
            }                                                                                      \
            if (round_st->iterations <= _iters_per_slot) {                                         \
                break;                                                                             \
            };                                                                                     \
                                                                                                   \
            /* Schedule again but with iterations decremented */                                   \
            round_st->iterations -= _iters_per_slot;                                               \
            if (enif_consume_timeslice(env, TIMESLICE_PERCENTAGE)) {                               \
                return enif_schedule_nif(env, HMAC_CTX_ROUND_NAME(_name), 0, PBKDF2_F_MD(_name),   \
                                         argc, argv);                                              \
            }                                                                                      \
        }                                                                                          \
                                                                                                   \
        /* Reform result into output buffer */                                                     \
        ERL_NIF_TERM erl_result;                                                                   \
        unsigned char *output = enif_make_new_binary(env, _hashsz, &erl_result);                   \
        if (output == NULL) {                                                                      \
            CLEANUP(_name)(round_st);                                                              \
            return enif_make_badarg(env);                                                          \
        }                                                                                          \
        memcpy(output, &round_st->result, _hashsz);                                                \
        /* We're done, so we can release the resource */                                           \
        CLEANUP(_name)(round_st);                                                                  \
        return erl_result;                                                                         \
                                                                                                   \
    error:                                                                                         \
        CLEANUP(_name)(round_st);                                                                  \
        return enif_make_badarg(env);                                                              \
    }                                                                                              \
                                                                                                   \
    /* Initialises the first iteration and prepares the state for PBKDF2_F_MD */                   \
    /* allocates the resource for the HMAC context and calls `PBKDF2_F_sha1` */                    \
    static inline ERL_NIF_TERM PBKDF2_F(_name)(                                                    \
        ErlNifEnv * env, HMAC_CTX_ROUND(_name) *const restrict round_st,                           \
        const EVP_MD *const restrict type, const uint8_t *const restrict pw, const size_t npw,     \
        const uint8_t *const restrict salt, const size_t nsalt, const uint32_t counter) {          \
        if (HMAC_INIT(_name)(round_st, type, pw, npw) != 0) {                                      \
            CLEANUP(_name)(round_st);                                                              \
            return mk_error(env, "hmac_init_failed");                                              \
        }                                                                                          \
                                                                                                   \
        round_st->ctx.inner = EVP_MD_CTX_new();                                                    \
        round_st->ctx.outer = EVP_MD_CTX_new();                                                    \
        if (!round_st->ctx.inner || !round_st->ctx.outer) {                                        \
            CLEANUP(_name)(round_st);                                                              \
            return mk_error(env, "ctx_allocation_failed");                                         \
        }                                                                                          \
                                                                                                   \
        if (!EVP_DigestInit_ex2(round_st->ctx.inner, type, NULL) ||                                \
            !EVP_DigestInit_ex2(round_st->ctx.outer, type, NULL)) {                                \
            CLEANUP(_name)(round_st);                                                              \
            return mk_error(env, "digest_init_failed");                                            \
        }                                                                                          \
                                                                                                   \
        uint8_t countbuf[4];                                                                       \
        write32_be(counter, countbuf);                                                             \
        /* Prepare loop-invariant padding block. */                                                \
        md_pad(round_st->Ublock, _blocksz, _hashsz, _blocksz + _hashsz);                           \
        /* First iteration:                                                                        \
         *   U_1 = PRF(P, S || INT_32_BE(i))                                                       \
         */                                                                                        \
        if (!EVP_MD_CTX_copy_ex(round_st->ctx.inner, round_st->startctx.inner) ||                  \
            !EVP_MD_CTX_copy_ex(round_st->ctx.outer, round_st->startctx.outer)) {                  \
            CLEANUP(_name)(round_st);                                                              \
            return mk_error(env, "ctx_copy_failed");                                               \
        }                                                                                          \
                                                                                                   \
        if (!EVP_DigestUpdate(round_st->ctx.inner, salt, nsalt) ||                                 \
            !EVP_DigestUpdate(round_st->ctx.inner, countbuf, sizeof(countbuf)) ||                  \
            !EVP_DigestFinal_ex(round_st->ctx.inner, round_st->Ublock, NULL)) {                    \
            CLEANUP(_name)(round_st);                                                              \
            return mk_error(env, "digest_update_failed");                                          \
        }                                                                                          \
                                                                                                   \
        if (!EVP_DigestUpdate(round_st->ctx.outer, round_st->Ublock, _hashsz) ||                   \
            !EVP_DigestFinal_ex(round_st->ctx.outer, round_st->Ublock, NULL)) {                    \
            CLEANUP(_name)(round_st);                                                              \
            return mk_error(env, "digest_final_failed");                                           \
        }                                                                                          \
                                                                                                   \
        if (!EVP_DigestInit_ex2(round_st->ctx.inner, NULL, NULL) ||                                \
            !EVP_DigestInit_ex2(round_st->ctx.outer, NULL, NULL)) {                                \
            CLEANUP(_name)(round_st);                                                              \
            return mk_error(env, "digest_init_ex2_failed");                                        \
        }                                                                                          \
        /* We have ran one iteration already */                                                    \
        --(round_st->iterations);                                                                  \
        memcpy(round_st->result, round_st->Ublock, _hashsz);                                       \
        ERL_NIF_TERM state_term = enif_make_resource(env, round_st);                               \
        const ERL_NIF_TERM tmp_argv[] = {state_term};                                              \
        return PBKDF2_F_MD(_name)(env, 1, tmp_argv);                                               \
    }                                                                                              \
                                                                                                   \
    /* Entry point, chooses the algorithm and initialises all values */                            \
    static inline ERL_NIF_TERM PBKDF2(_name)(ErlNifEnv * env, const uint8_t *restrict pw,          \
                                             const size_t npw, const uint8_t *restrict salt,       \
                                             const size_t nsalt, const uint32_t iterations,        \
                                             const uint32_t counter) {                             \
        const pbkdf2_st *mod_st = enif_priv_data(env);                                             \
        const EVP_MD *const type = mod_st->MD_NAME(_name);                                         \
        HMAC_CTX_ROUND(_name) *const restrict round_st =                                           \
            enif_alloc_resource(mod_st->HMAC_CTX_ROUND_RES(_name), sizeof(HMAC_CTX_ROUND(_name))); \
        if (round_st == NULL)                                                                      \
            return mk_error(env, "alloc_failed");                                                  \
        round_st->ctx.inner = NULL;                                                                \
        round_st->ctx.outer = NULL;                                                                \
        round_st->startctx.inner = NULL;                                                           \
        round_st->startctx.outer = NULL;                                                           \
        round_st->iterations = iterations;                                                         \
        return PBKDF2_F(_name)(env, round_st, type, pw, npw, salt, nsalt, counter);                \
    }

/* Hash method |  Blocksize (in bytes) |  Hash length (in bytes)
 * SHA-224     | 64                    | 28^
 * SHA-256     | 64                    | 32
 * SHA-384     | 128                   | 48^
 * SHA-512     | 128                   | 64
 * SHA3-224    | 144                   | 28
 * SHA3-256    | 136                   | 32
 * SHA3-384    | 104                   | 48
 * SHA3-512    | 72                    | 64
 */

/* On the following machine:
 * - CPU Information: Intel(R) Core(TM) i9-8950HK CPU @ 2.90GHz
 * - Number of Available Cores: 12
 * - Available memory: 30.97 GB
 * - Elixir 1.18.2
 * - Erlang 27.2.2
 *
 * We look for how many iterations we can do in a slot of 1ms:
 *                               ips        average  deviation         median         99th %
 * SHA1/3350-iterations       1.04 K      964.86 μs    ±17.04%      911.91 μs     1728.66 μs
 * SHA256/2100-iterations     1.01 K      988.12 μs    ±15.21%      938.68 μs     1669.52 μs
 * SHA512/1600-iterations     1.02 K      983.10 μs    ±15.88%      933.49 μs     1668.32 μs
 * SHA3_256/1060-iterations   1.04 K      958.75 μs    ±14.25%      918.95 μs     1534.53 μs
 * SHA3_512/1060-iterations   1.01 K      990.36 μs    ±13.68%      957.71 μs     1547.29 μs
 *
 * Also, we want to report percentage every 5% (TIMESLICE_PERCENTAGE).
 * We therefore get that a slot in between iterations should take MAX/SLICE iterations in a slot.
 */

DECL_PBKDF2(sha1, SHA_CBLOCK, SHA_DIGEST_LENGTH, 3350 / SLICE)
DECL_PBKDF2(sha224, SHA256_CBLOCK, SHA224_DIGEST_LENGTH, 2100 / SLICE)
DECL_PBKDF2(sha256, SHA256_CBLOCK, SHA256_DIGEST_LENGTH, 2100 / SLICE)
DECL_PBKDF2(sha384, SHA512_CBLOCK, SHA384_DIGEST_LENGTH, 1600 / SLICE)
DECL_PBKDF2(sha512, SHA512_CBLOCK, SHA512_DIGEST_LENGTH, 1600 / SLICE)
DECL_PBKDF2(sha3_224, 144, SHA224_DIGEST_LENGTH, 1060 / SLICE)
DECL_PBKDF2(sha3_256, 136, SHA256_DIGEST_LENGTH, 1060 / SLICE)
DECL_PBKDF2(sha3_384, 104, SHA384_DIGEST_LENGTH, 1080 / SLICE)
DECL_PBKDF2(sha3_512, 72, SHA512_DIGEST_LENGTH, 1080 / SLICE)

static int load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info) {
    (void)load_info;
    pbkdf2_st *mod_st = enif_alloc(sizeof(pbkdf2_st));
    if (mod_st == NULL)
        return 1;
    mod_st->MD_NAME(sha1) = NULL;
    mod_st->MD_NAME(sha224) = NULL;
    mod_st->MD_NAME(sha256) = NULL;
    mod_st->MD_NAME(sha384) = NULL;
    mod_st->MD_NAME(sha512) = NULL;
    mod_st->MD_NAME(sha3_224) = NULL;
    mod_st->MD_NAME(sha3_256) = NULL;
    mod_st->MD_NAME(sha3_384) = NULL;
    mod_st->MD_NAME(sha3_512) = NULL;

    mod_st->atom_sha = enif_make_atom(env, "sha");
    mod_st->atom_sha224 = enif_make_atom(env, "sha224");
    mod_st->atom_sha256 = enif_make_atom(env, "sha256");
    mod_st->atom_sha384 = enif_make_atom(env, "sha384");
    mod_st->atom_sha512 = enif_make_atom(env, "sha512");
    mod_st->atom_sha3_224 = enif_make_atom(env, "sha3_224");
    mod_st->atom_sha3_256 = enif_make_atom(env, "sha3_256");
    mod_st->atom_sha3_384 = enif_make_atom(env, "sha3_384");
    mod_st->atom_sha3_512 = enif_make_atom(env, "sha3_512");

    /* Pre-fetch all the hash functions */
    mod_st->MD_NAME(sha1) = EVP_MD_fetch(NULL, "SHA1", NULL);
    if (NULL == mod_st->MD_NAME(sha1))
        goto cleanup;
    mod_st->MD_NAME(sha224) = EVP_MD_fetch(NULL, "SHA224", NULL);
    if (NULL == mod_st->MD_NAME(sha224))
        goto cleanup;
    mod_st->MD_NAME(sha256) = EVP_MD_fetch(NULL, "SHA256", NULL);
    if (NULL == mod_st->MD_NAME(sha256))
        goto cleanup;
    mod_st->MD_NAME(sha384) = EVP_MD_fetch(NULL, "SHA384", NULL);
    if (NULL == mod_st->MD_NAME(sha384))
        goto cleanup;
    mod_st->MD_NAME(sha512) = EVP_MD_fetch(NULL, "SHA512", NULL);
    if (NULL == mod_st->MD_NAME(sha512))
        goto cleanup;
    mod_st->MD_NAME(sha3_224) = EVP_MD_fetch(NULL, "SHA3-224", NULL);
    if (NULL == mod_st->MD_NAME(sha3_224))
        goto cleanup;
    mod_st->MD_NAME(sha3_256) = EVP_MD_fetch(NULL, "SHA3-256", NULL);
    if (NULL == mod_st->MD_NAME(sha3_256))
        goto cleanup;
    mod_st->MD_NAME(sha3_384) = EVP_MD_fetch(NULL, "SHA3-384", NULL);
    if (NULL == mod_st->MD_NAME(sha3_384))
        goto cleanup;
    mod_st->MD_NAME(sha3_512) = EVP_MD_fetch(NULL, "SHA3-512", NULL);
    if (NULL == mod_st->MD_NAME(sha3_512))
        goto cleanup;

    mod_st->HMAC_CTX_ROUND_RES(sha1) = enif_open_resource_type(
        env, NULL, HMAC_CTX_ROUND_NAME(sha1), NULL, ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL);
    if (NULL == mod_st->HMAC_CTX_ROUND_RES(sha1))
        goto cleanup;
    mod_st->HMAC_CTX_ROUND_RES(sha224) =
        enif_open_resource_type(env, NULL, HMAC_CTX_ROUND_NAME(sha224), NULL,
                                ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL);
    if (NULL == mod_st->HMAC_CTX_ROUND_RES(sha224))
        goto cleanup;
    mod_st->HMAC_CTX_ROUND_RES(sha256) =
        enif_open_resource_type(env, NULL, HMAC_CTX_ROUND_NAME(sha256), NULL,
                                ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL);
    if (NULL == mod_st->HMAC_CTX_ROUND_RES(sha256))
        goto cleanup;
    mod_st->HMAC_CTX_ROUND_RES(sha384) =
        enif_open_resource_type(env, NULL, HMAC_CTX_ROUND_NAME(sha384), NULL,
                                ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL);
    if (NULL == mod_st->HMAC_CTX_ROUND_RES(sha384))
        goto cleanup;
    mod_st->HMAC_CTX_ROUND_RES(sha512) =
        enif_open_resource_type(env, NULL, HMAC_CTX_ROUND_NAME(sha512), NULL,
                                ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL);
    if (NULL == mod_st->HMAC_CTX_ROUND_RES(sha512))
        goto cleanup;

    mod_st->HMAC_CTX_ROUND_RES(sha3_224) =
        enif_open_resource_type(env, NULL, HMAC_CTX_ROUND_NAME(sha3_224), NULL,
                                ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL);
    if (NULL == mod_st->HMAC_CTX_ROUND_RES(sha3_224))
        goto cleanup;
    mod_st->HMAC_CTX_ROUND_RES(sha3_256) =
        enif_open_resource_type(env, NULL, HMAC_CTX_ROUND_NAME(sha3_256), NULL,
                                ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL);
    if (NULL == mod_st->HMAC_CTX_ROUND_RES(sha3_256))
        goto cleanup;
    mod_st->HMAC_CTX_ROUND_RES(sha3_384) =
        enif_open_resource_type(env, NULL, HMAC_CTX_ROUND_NAME(sha3_384), NULL,
                                ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL);
    if (NULL == mod_st->HMAC_CTX_ROUND_RES(sha3_384))
        goto cleanup;
    mod_st->HMAC_CTX_ROUND_RES(sha3_512) =
        enif_open_resource_type(env, NULL, HMAC_CTX_ROUND_NAME(sha3_512), NULL,
                                ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL);
    if (NULL == mod_st->HMAC_CTX_ROUND_RES(sha3_512))
        goto cleanup;

    *priv_data = (void *)mod_st;

    return 0;

cleanup:
    // Cleanup allocated memory in case of failure
    if (mod_st->MD_NAME(sha1) != NULL)
        EVP_MD_free(mod_st->MD_NAME(sha1));
    if (mod_st->MD_NAME(sha224) != NULL)
        EVP_MD_free(mod_st->MD_NAME(sha224));
    if (mod_st->MD_NAME(sha256) != NULL)
        EVP_MD_free(mod_st->MD_NAME(sha256));
    if (mod_st->MD_NAME(sha384) != NULL)
        EVP_MD_free(mod_st->MD_NAME(sha384));
    if (mod_st->MD_NAME(sha512) != NULL)
        EVP_MD_free(mod_st->MD_NAME(sha512));
    if (mod_st->MD_NAME(sha3_224) != NULL)
        EVP_MD_free(mod_st->MD_NAME(sha3_224));
    if (mod_st->MD_NAME(sha3_256) != NULL)
        EVP_MD_free(mod_st->MD_NAME(sha3_256));
    if (mod_st->MD_NAME(sha3_384) != NULL)
        EVP_MD_free(mod_st->MD_NAME(sha3_384));
    if (mod_st->MD_NAME(sha3_512) != NULL)
        EVP_MD_free(mod_st->MD_NAME(sha3_512));
    enif_free(mod_st);
    return 1;
}

static int reload(ErlNifEnv *env, void **priv, ERL_NIF_TERM info) {
    (void)env;
    (void)priv;
    (void)info;
    return 0;
}

static int upgrade(ErlNifEnv *env, void **priv, void **old_priv, ERL_NIF_TERM info) {
    (void)old_priv;
    return load(env, priv, info);
}

static void unload(ErlNifEnv *env, void *priv) {
    (void)env;
    pbkdf2_st *mod_st = (pbkdf2_st *)priv;
    EVP_MD_free(mod_st->MD_NAME(sha1));
    EVP_MD_free(mod_st->MD_NAME(sha224));
    EVP_MD_free(mod_st->MD_NAME(sha256));
    EVP_MD_free(mod_st->MD_NAME(sha384));
    EVP_MD_free(mod_st->MD_NAME(sha512));
    EVP_MD_free(mod_st->MD_NAME(sha3_224));
    EVP_MD_free(mod_st->MD_NAME(sha3_256));
    EVP_MD_free(mod_st->MD_NAME(sha3_384));
    EVP_MD_free(mod_st->MD_NAME(sha3_512));
    enif_free(priv);
    return;
}

static ERL_NIF_TERM pbkdf2_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 5)
        return enif_make_badarg(env);

    ErlNifBinary password;
    if (!enif_inspect_binary(env, argv[1], &password))
        return mk_error(env, "bad_password");

    ErlNifBinary salt;
    if (!enif_inspect_binary(env, argv[2], &salt))
        return mk_error(env, "bad_salt");

    int iteration_count;
    if (!enif_get_int(env, argv[3], &iteration_count))
        return mk_error(env, "bad_iteration_count");
    if (iteration_count <= 0)
        return mk_error(env, "bad_iteration_count");

    int counter;
    if (!enif_get_int(env, argv[4], &counter))
        return mk_error(env, "bad_block_counter");
    if (counter <= 0)
        return mk_error(env, "bad_block_counter");

    pbkdf2_st *mod_st = (pbkdf2_st *)enif_priv_data(env);

    if (enif_is_identical(argv[0], mod_st->atom_sha)) {
        return PBKDF2(sha1)(env, password.data, password.size, salt.data, salt.size,
                            iteration_count, counter);
    } else if (enif_is_identical(argv[0], mod_st->atom_sha224)) {
        return PBKDF2(sha224)(env, password.data, password.size, salt.data, salt.size,
                              iteration_count, counter);
    } else if (enif_is_identical(argv[0], mod_st->atom_sha256)) {
        return PBKDF2(sha256)(env, password.data, password.size, salt.data, salt.size,
                              iteration_count, counter);
    } else if (enif_is_identical(argv[0], mod_st->atom_sha384)) {
        return PBKDF2(sha384)(env, password.data, password.size, salt.data, salt.size,
                              iteration_count, counter);
    } else if (enif_is_identical(argv[0], mod_st->atom_sha512)) {
        return PBKDF2(sha512)(env, password.data, password.size, salt.data, salt.size,
                              iteration_count, counter);
    } else if (enif_is_identical(argv[0], mod_st->atom_sha3_224)) {
        return PBKDF2(sha3_224)(env, password.data, password.size, salt.data, salt.size,
                                iteration_count, counter);
    } else if (enif_is_identical(argv[0], mod_st->atom_sha3_256)) {
        return PBKDF2(sha3_256)(env, password.data, password.size, salt.data, salt.size,
                                iteration_count, counter);
    } else if (enif_is_identical(argv[0], mod_st->atom_sha3_384)) {
        return PBKDF2(sha3_384)(env, password.data, password.size, salt.data, salt.size,
                                iteration_count, counter);
    } else if (enif_is_identical(argv[0], mod_st->atom_sha3_512)) {
        return PBKDF2(sha3_512)(env, password.data, password.size, salt.data, salt.size,
                                iteration_count, counter);
    } else {
        return mk_error(env, "bad_hash");
    }
}

static ErlNifFunc fastpbkdf2_nif_funcs[] = {{"pbkdf2_block", 5, pbkdf2_nif, 0}};

ERL_NIF_INIT(fast_pbkdf2, fastpbkdf2_nif_funcs, load, reload, upgrade, unload);
