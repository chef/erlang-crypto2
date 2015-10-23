#include <openssl/opensslconf.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include "crypto_callback.h"
#include "erl_nif.h"

#ifdef DEBUG
#define OPENSSL_PRINT_ERROR(msg) print_ssl_error(msg)
static void print_ssl_error(const char* msg) {
    char err[256];
    ERR_error_string_n(ERR_get_error(), err, 256);
    enif_fprintf(stderr, "%s: %s\n", msg, err);
}
#else
#define OPENSSL_PRINT_ERROR(msg)
#endif

static ERL_NIF_TERM atom_error;
static ERL_NIF_TERM atom_true;
static ERL_NIF_TERM atom_false;
static ERL_NIF_TERM atom_sha256;
static ERL_NIF_TERM atom_sha512;
static ERL_NIF_TERM atom_rsa_no_padding;
static ERL_NIF_TERM atom_rsa_pkcs1_padding;
static ERL_NIF_TERM atom_rsa_pkcs1_oaep_padding;

// ------ erlrt_evp_md_ctx ------
//  This will be the nif resource type for
//  erl_evp_md_ctx.
static ErlNifResourceType* erlrt_evp_md_ctx;

typedef struct erl_evp_md_ctx {
    EVP_MD_CTX* ctx;
} erl_evp_md_ctx_t;
// ------------------------------

static ERL_NIF_TERM sha1_init(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM sha256_init(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM sha512_init(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM hash_update(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM hash_final(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM rand_bytes(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM rsa_sign(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM rsa_verify(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM rsa_public_crypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM rsa_private_crypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

// Helpers
static ERL_NIF_TERM evp_md_init(ErlNifEnv* env, const EVP_MD* md);
static ERL_NIF_TERM evp_md_update(ErlNifEnv* env, erl_evp_md_ctx_t* erl_md_ctx,
    void* d, size_t cnt);
static ERL_NIF_TERM evp_md_final(ErlNifEnv* env, erl_evp_md_ctx_t* erl_md_ctx);
static int get_atom_nid(ERL_NIF_TERM key);
static int get_rsa_private_key(ErlNifEnv* env, ERL_NIF_TERM key, RSA *rsa);
static int get_rsa_public_key(ErlNifEnv* env, ERL_NIF_TERM key, RSA *rsa);
static int get_bn_from_bin(ErlNifEnv* env, ERL_NIF_TERM term, BIGNUM** bnp);
static int rsa_pad(ERL_NIF_TERM term, int* padding);

static ErlNifFunc nif_funcs[] = {
    { "sha1_init", 0, sha1_init },
    { "sha256_init", 0, sha256_init },
    { "sha512_init", 0, sha512_init },
    { "hash_update", 2, hash_update },
    { "hash_final", 1, hash_final },
    { "rand_bytes_nif", 1, rand_bytes },
    { "rsa_sign", 3, rsa_sign},
    { "rsa_verify", 4, rsa_verify},
    { "rsa_public_crypt", 4, rsa_public_crypt },
    { "rsa_private_crypt", 4, rsa_private_crypt },
};

static ERL_NIF_TERM sha1_init(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    return evp_md_init(env, EVP_sha1());
}

static ERL_NIF_TERM sha256_init(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    return evp_md_init(env, EVP_sha256());
}

static ERL_NIF_TERM sha512_init(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    return evp_md_init(env, EVP_sha512());
}

/*
 * hash_update(Context, Data) -> NewContext
 */
static ERL_NIF_TERM hash_update(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary ibin;
    erl_evp_md_ctx_t* erl_md_ctx;

    if (!enif_get_resource(env, argv[0], erlrt_evp_md_ctx, (void**)&erl_md_ctx)) {
        return enif_make_badarg(env);
    }

    if (!enif_inspect_iolist_as_binary(env, argv[1], &ibin)) {
        return enif_make_badarg(env);
    }

    return evp_md_update(env, erl_md_ctx, ibin.data, ibin.size);
}

/*
 * hash_final(Context) -> Digest
 */
static ERL_NIF_TERM hash_final(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    erl_evp_md_ctx_t* erl_md_ctx;

    if (!enif_get_resource(env, argv[0], erlrt_evp_md_ctx, (void**)&erl_md_ctx)) {
        return enif_make_badarg(env);
    }

    return evp_md_final(env, erl_md_ctx);
}

static ERL_NIF_TERM evp_md_init(ErlNifEnv* env, const EVP_MD* md)
{
    ERL_NIF_TERM term;
    erl_evp_md_ctx_t* erl_md_ctx = (erl_evp_md_ctx_t*)enif_alloc_resource(
        erlrt_evp_md_ctx, sizeof(erl_evp_md_ctx_t));

    term = enif_make_resource(env, erl_md_ctx);
    enif_release_resource(erl_md_ctx);

    if (!(erl_md_ctx->ctx = EVP_MD_CTX_create())) {
        return atom_error;
    }

    if (!EVP_DigestInit_ex(erl_md_ctx->ctx, md, NULL)) {
        return atom_error;
    }

    return term;
}

static ERL_NIF_TERM evp_md_update(ErlNifEnv* env, erl_evp_md_ctx_t* erl_md_ctx,
    void* d, size_t cnt)
{
    ERL_NIF_TERM term;
    // We want to create a copy of the data structure because immutable
    erl_evp_md_ctx_t* new_erl_md_ctx = (erl_evp_md_ctx_t*)enif_alloc_resource(
        erlrt_evp_md_ctx, sizeof(erl_evp_md_ctx_t));

    term = enif_make_resource(env, new_erl_md_ctx);
    enif_release_resource(new_erl_md_ctx);

    if (!(new_erl_md_ctx->ctx = EVP_MD_CTX_create())) {
        return atom_error;
    }

    if (!EVP_MD_CTX_copy_ex(new_erl_md_ctx->ctx, erl_md_ctx->ctx)) {
        return atom_error;
    }

    if (!EVP_DigestUpdate(new_erl_md_ctx->ctx, d, cnt)) {
        return atom_error;
    }

    return term;
}

static ERL_NIF_TERM evp_md_final(ErlNifEnv* env, erl_evp_md_ctx_t* erl_md_ctx)
{
    ERL_NIF_TERM ret;
    EVP_MD_CTX* ctx;

    // Make a copy so we do not change the context
    if (!(ctx = EVP_MD_CTX_create())) {
        return atom_error;
    }

    if (!EVP_MD_CTX_copy_ex(ctx, erl_md_ctx->ctx)) {
        return atom_error;
    }

    if (!EVP_DigestFinal_ex(
            ctx,
            enif_make_new_binary(env, EVP_MD_CTX_size(ctx), &ret), NULL)) {
        ret = atom_error;
    }

    EVP_MD_CTX_destroy(ctx);

    return ret;
}

static ERL_NIF_TERM rand_bytes(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    unsigned int bytes;
    ERL_NIF_TERM ret;

    if (!enif_get_uint(env, argv[0], &bytes)) {
        return enif_make_badarg(env);
    }

    if (RAND_bytes(enif_make_new_binary(env, bytes, &ret), bytes)) {
        return ret;
    }
    else {
        return atom_error;
    }
}

/*
 * rsa_sign(DigestType=(sha256|sha512), Msg=binary(), Key=rsa_private())
 */
static ERL_NIF_TERM rsa_sign(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary ibin;
    ErlNifBinary ret_bin;
    RSA* rsa;
    unsigned int sig_len;
    int type;
    int status;

    if ((type = get_atom_nid(argv[0])) == NID_undef) {
        return enif_make_badarg(env);
    }

    if (!enif_inspect_binary(env, argv[1], &ibin)) {
        return enif_make_badarg(env);
    }

    rsa = RSA_new();
    if (!rsa) {
        RSA_free(rsa);
        return atom_error;
    }

    if (!get_rsa_private_key(env, argv[2], rsa)) {
        RSA_free(rsa);
        return enif_make_badarg(env);
    }

    enif_alloc_binary(RSA_size(rsa), &ret_bin);

    status = RSA_sign(type, ibin.data, ibin.size, ret_bin.data, &sig_len, rsa);

    RSA_free(rsa);

    if (status) {
        if (sig_len != ret_bin.size) {
            enif_realloc_binary(&ret_bin, sig_len);
        }
        return enif_make_binary(env, &ret_bin);
    } else {
        OPENSSL_PRINT_ERROR("sign failed");
        enif_release_binary(&ret_bin);
        return atom_error;
    }

}

/*
 * rsa_verify(DigestType=(sha256|sha512), Msg=binary(),
 *            Signature=binary(), Key=rsa_public()) -> boolean()
 */
static ERL_NIF_TERM rsa_verify(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary msg;
    ErlNifBinary sig;
    RSA* rsa;
    int type;
    int matches;

    if ((type = get_atom_nid(argv[0])) == NID_undef) {
        return enif_make_badarg(env);
    }

    if (!enif_inspect_binary(env, argv[1], &msg)) {
        return enif_make_badarg(env);
    }

    if (!enif_inspect_binary(env, argv[2], &sig)) {
        return enif_make_badarg(env);
    }

    rsa = RSA_new();
    if (!rsa) {
        RSA_free(rsa);
        return atom_error;
    }

    if (!get_rsa_public_key(env, argv[3], rsa)) {
        RSA_free(rsa);
        return enif_make_badarg(env);
    }

    matches = RSA_verify(type, msg.data, msg.size, sig.data, sig.size, rsa);
    RSA_free(rsa);

    return (matches == 1 ? atom_true : atom_false);
}

static int get_atom_nid(ERL_NIF_TERM term)
{
    if (term == atom_sha256) {
        return NID_sha256;
    } else if(term == atom_sha512) {
        return NID_sha512;
    } else {
        return NID_undef;
    }
}

static int get_rsa_public_key(ErlNifEnv* env, ERL_NIF_TERM key, RSA *rsa)
{
    /* key=[E,N] */
    ERL_NIF_TERM head, tail;

    if (!enif_get_list_cell(env, key, &head, &tail)
            || !get_bn_from_bin(env, head, &rsa->e)
            || !enif_get_list_cell(env, tail, &head, &tail)
            || !get_bn_from_bin(env, head, &rsa->n)
            || !enif_is_empty_list(env, tail)) {

        return 0;
    }
    return 1;
}
// Verbatim from crypto.c in OTP
static int get_rsa_private_key(ErlNifEnv* env, ERL_NIF_TERM key, RSA *rsa)
{
    /* key=[E,N,D]|[E,N,D,P1,P2,E1,E2,C] */
    ERL_NIF_TERM head, tail;

    if (!enif_get_list_cell(env, key, &head, &tail)
            || !get_bn_from_bin(env, head, &rsa->e)
            || !enif_get_list_cell(env, tail, &head, &tail)
            || !get_bn_from_bin(env, head, &rsa->n)
            || !enif_get_list_cell(env, tail, &head, &tail)
            || !get_bn_from_bin(env, head, &rsa->d)
            || (!enif_is_empty_list(env, tail) &&
                (!enif_get_list_cell(env, tail, &head, &tail)
                 || !get_bn_from_bin(env, head, &rsa->p)
                 || !enif_get_list_cell(env, tail, &head, &tail)
                 || !get_bn_from_bin(env, head, &rsa->q)
                 || !enif_get_list_cell(env, tail, &head, &tail)
                 || !get_bn_from_bin(env, head, &rsa->dmp1)
                 || !enif_get_list_cell(env, tail, &head, &tail)
                 || !get_bn_from_bin(env, head, &rsa->dmq1)
                 || !enif_get_list_cell(env, tail, &head, &tail)
                 || !get_bn_from_bin(env, head, &rsa->iqmp)
                 || !enif_is_empty_list(env, tail)))) {
        return 0;
    }
    return 1;
}

// Almost verbatim from crypto.c in OTP
static int get_bn_from_bin(ErlNifEnv* env, ERL_NIF_TERM term, BIGNUM** bnp)
{
    ErlNifBinary bin;
    if (!enif_inspect_binary(env,term,&bin)) {
        return 0;
    }
    *bnp = BN_bin2bn(bin.data, bin.size, NULL);
    return 1;
}

static int rsa_pad(ERL_NIF_TERM term, int* padding)
{
    if (term == atom_rsa_pkcs1_padding) {
        *padding = RSA_PKCS1_PADDING;
    }
    else if (term == atom_rsa_pkcs1_oaep_padding) {
        *padding = RSA_PKCS1_OAEP_PADDING;
    }
    else if (term == atom_rsa_no_padding) {
        *padding = RSA_NO_PADDING;
    }
    else {
        return 0;
    }
    return 1;
}

static ERL_NIF_TERM rsa_public_crypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{/* (Data, PublKey=[E,N], Padding, IsEncrypt) */
    ErlNifBinary data_bin, ret_bin;
    ERL_NIF_TERM head, tail;
    int padding, i;
    RSA* rsa;

    rsa = RSA_new();

    if (!enif_inspect_binary(env, argv[0], &data_bin)
            || !enif_get_list_cell(env, argv[1], &head, &tail)
            || !get_bn_from_bin(env, head, &rsa->e)
            || !enif_get_list_cell(env, tail, &head, &tail)
            || !get_bn_from_bin(env, head, &rsa->n)
            || !enif_is_empty_list(env,tail)
            || !rsa_pad(argv[2], &padding)) {

        RSA_free(rsa);
        return enif_make_badarg(env);
    }

    enif_alloc_binary(RSA_size(rsa), &ret_bin);

    if (argv[3] == atom_true) {
        i = RSA_public_encrypt(data_bin.size, data_bin.data,
                ret_bin.data, rsa, padding);
    }
    else {
        i = RSA_public_decrypt(data_bin.size, data_bin.data,
                ret_bin.data, rsa, padding);
        if (i > 0) {
            enif_realloc_binary(&ret_bin, i);
        }
    }
    RSA_free(rsa);
    if (i > 0) {
        return enif_make_binary(env,&ret_bin);
    }
    else {
        enif_release_binary(&ret_bin);
        return atom_error;
    }
}

static ERL_NIF_TERM rsa_private_crypt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{/* (Data, Key=[E,N,D]|[E,N,D,P1,P2,E1,E2,C], Padding, IsEncrypt) */
    ErlNifBinary data_bin, ret_bin;
    int padding, i;
    RSA* rsa;

    rsa = RSA_new();

    if (!enif_inspect_binary(env, argv[0], &data_bin)
            || !get_rsa_private_key(env, argv[1], rsa)
            || !rsa_pad(argv[2], &padding)) {

        RSA_free(rsa);
        return enif_make_badarg(env);
    }

    enif_alloc_binary(RSA_size(rsa), &ret_bin);

    if (argv[3] == atom_true) {
        i = RSA_private_encrypt(data_bin.size, data_bin.data,
                ret_bin.data, rsa, padding);
    }
    else {
        i = RSA_private_decrypt(data_bin.size, data_bin.data,
                ret_bin.data, rsa, padding);
        if (i > 0) {
            enif_realloc_binary(&ret_bin, i);
        }
    }
    RSA_free(rsa);
    if (i > 0) {
        return enif_make_binary(env,&ret_bin);
    }
    else {
        enif_release_binary(&ret_bin);
        return atom_error;
    }
}

static void evp_md_destructor(ErlNifEnv* env, erl_evp_md_ctx_t* obj)
{
    EVP_MD_CTX_destroy(obj->ctx);
}

static int init(ErlNifEnv* env, ERL_NIF_TERM load_info)
{
    struct crypto_callbacks* ccb;

    /*
     * Initialize atoms
     */
    atom_error  = enif_make_atom(env, "error");
    atom_true   = enif_make_atom(env, "true");
    atom_false  = enif_make_atom(env, "false");
    atom_sha256 = enif_make_atom(env, "sha256");
    atom_sha512 = enif_make_atom(env, "sha512");
    atom_rsa_pkcs1_padding = enif_make_atom(env,"rsa_pkcs1_padding");
    atom_rsa_pkcs1_oaep_padding = enif_make_atom(env,"rsa_pkcs1_oaep_padding");
    atom_rsa_no_padding = enif_make_atom(env,"rsa_no_padding");

    /*
     * Initialize resource types
     */
    erlrt_evp_md_ctx = enif_open_resource_type(
        env, "crypto2",
        "erlrt_evp_md_ctx",
        (ErlNifResourceDtor*)evp_md_destructor,
        ERL_NIF_RT_CREATE,
        NULL);

    /*
     * Initialize threading context
     */
    ccb = get_crypto_callbacks(CRYPTO_num_locks());
    if (!ccb) {
        return 1;
    }

    CRYPTO_set_mem_functions(ccb->crypto_alloc, ccb->crypto_realloc, ccb->crypto_free);
    CRYPTO_set_locking_callback(ccb->locking_function);
    CRYPTO_set_id_callback(ccb->id_function);
    CRYPTO_set_dynlock_create_callback(ccb->dyn_create_function);
    CRYPTO_set_dynlock_lock_callback(ccb->dyn_lock_function);
    CRYPTO_set_dynlock_destroy_callback(ccb->dyn_destroy_function);

#ifdef CRYPTO_FIPS_MODE
    FIPS_mode_set(1);
#endif

#ifdef DEBUG
    SSL_load_error_strings();
#endif

    return 1;
}

static int load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info)
{
    if (!init(env, load_info)) {
        return -1;
    }
    *priv_data = NULL;
    return 0;
}

ERL_NIF_INIT(crypto2, nif_funcs, load, NULL, NULL, NULL)
