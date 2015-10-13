#include <openssl/opensslconf.h>
#include <openssl/evp.h>
#include "crypto_callback.h"
#include "erl_nif.h"

static ERL_NIF_TERM atom_error;


// ------ erlrt_evp_md_ctx ------
//  This will be the nif resource type for
//  erl_evp_md_ctx.
static ErlNifResourceType* erlrt_evp_md_ctx;

typedef struct erl_evp_md_ctx {
    EVP_MD_CTX* ctx;
} erl_evp_md_ctx_t;
// ------------------------------

static ERL_NIF_TERM sha256_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ErlNifFunc nif_funcs[] = {
    {"sha256_nif", 1, sha256_nif}
};

/*
 * sha256(iodata()) -> binary().
 */
static ERL_NIF_TERM sha256_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary ibin;
    ERL_NIF_TERM ret;
    EVP_MD_CTX* ctx;
    const EVP_MD* md;

    if (!enif_inspect_iolist_as_binary(env, argv[0], &ibin)) {
        return enif_make_badarg(env);
    }

    md = EVP_sha256();
    ctx = EVP_MD_CTX_create();

    if(!EVP_DigestInit_ex(ctx, md, NULL)) {
        return atom_error;
    }

    if(!EVP_DigestUpdate(ctx, ibin.data, ibin.size)) {
        return atom_error;
    }

    if(!EVP_DigestFinal_ex(
                ctx, enif_make_new_binary(env, EVP_MD_size(md), &ret), NULL)) {
        return atom_error;
    }

    EVP_MD_CTX_destroy(ctx);

    return ret;
}

static erl_evp_md_ctx_t* evp_md_init(const EVP_MD* md) {
    erl_evp_md_ctx_t* erl_md_ctx = (erl_evp_md_ctx_t*)enif_alloc_resource(
            erlrt_evp_md_ctx, sizeof(erl_evp_md_ctx_t));
    erl_md_ctx->ctx = EVP_MD_CTX_create();

    if(!EVP_DigestInit_ex(erl_md_ctx->ctx, md, NULL)) {
        return atom_error;
    }

    return erl_md_ctx;
}

static void evp_md_destructor(ErlNifEnv* env, erl_evp_md_ctx_t* obj) {
    EVP_MD_CTX_destroy(obj->ctx);
}

static int init(ErlNifEnv* env, ERL_NIF_TERM load_info) {
    struct crypto_callbacks* ccb;

    /*
     * Initialize atoms
     */
    atom_error = enif_make_atom(env, "error");

    /*
     * Initialize resource types
     */
    erlrt_evp_md_ctx = enif_open_resource_type(
            env, "crypto2",
            "erlrt_evp_md_ctx",
            (ErlNifResourceDtor)evp_md_destructor,
            ERL_NIF_RT_CREATE,
            NULL);

    /*
     * Initialize threading context
     */
    ccb = get_crypto_callbacks(CRYPTO_num_locks());
    if(!ccb) {
        return 1;
    }

    CRYPTO_set_mem_functions(ccb->crypto_alloc, ccb->crypto_realloc, ccb->crypto_free);
    CRYPTO_set_locking_callback(ccb->locking_function);
    CRYPTO_set_id_callback(ccb->id_function);
    CRYPTO_set_dynlock_create_callback(ccb->dyn_create_function);
    CRYPTO_set_dynlock_lock_callback(ccb->dyn_lock_function);
    CRYPTO_set_dynlock_destroy_callback(ccb->dyn_destroy_function);

    return 1;
}

static int load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info) {
    if(!init(env, load_info)) {
        return -1;
    }
    *priv_data = NULL;
    return 0;
}

ERL_NIF_INIT(crypto2, nif_funcs, load, NULL, NULL, NULL)
