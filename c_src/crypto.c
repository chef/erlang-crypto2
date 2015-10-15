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

static ERL_NIF_TERM sha256_init(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM sha512_init(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM hash_update(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM hash_final(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

// Helpers
static ERL_NIF_TERM evp_md_init(ErlNifEnv* env, const EVP_MD* md);
static ERL_NIF_TERM evp_md_update(ErlNifEnv* env, erl_evp_md_ctx_t* erl_md_ctx,
        void* d, size_t cnt);
static ERL_NIF_TERM evp_md_final(ErlNifEnv* env, erl_evp_md_ctx_t* erl_md_ctx);

static ErlNifFunc nif_funcs[] = {
    {"sha256_init", 0, sha256_init},
    {"sha512_init", 0, sha512_init},
    {"hash_update", 2, hash_update},
    {"hash_final", 1, hash_final},
};

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

    if(!enif_get_resource(env, argv[0], erlrt_evp_md_ctx, (void**)&erl_md_ctx)) {
        return enif_make_badarg(env);
    }

    if(!enif_inspect_iolist_as_binary(env, argv[1], &ibin)) {
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

    if(!enif_get_resource(env, argv[0], erlrt_evp_md_ctx, (void**)&erl_md_ctx)) {
        return enif_make_badarg(env);
    }

    return evp_md_final(env, erl_md_ctx);
}

static ERL_NIF_TERM evp_md_init(ErlNifEnv* env, const EVP_MD* md) {
    ERL_NIF_TERM term;
    erl_evp_md_ctx_t* erl_md_ctx = (erl_evp_md_ctx_t*)enif_alloc_resource(
            erlrt_evp_md_ctx, sizeof(erl_evp_md_ctx_t));

    term = enif_make_resource(env, erl_md_ctx);
    enif_release_resource(erl_md_ctx);

    erl_md_ctx->ctx = EVP_MD_CTX_create();

    if(!EVP_DigestInit_ex(erl_md_ctx->ctx, md, NULL)) {
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

    new_erl_md_ctx->ctx = EVP_MD_CTX_create();

    if(!EVP_MD_CTX_copy_ex(new_erl_md_ctx->ctx, erl_md_ctx->ctx)) {
        return atom_error;
    }

    if(!EVP_DigestUpdate(new_erl_md_ctx->ctx, d, cnt)) {
        return atom_error;
    }

    return term;
}

static ERL_NIF_TERM evp_md_final(ErlNifEnv* env, erl_evp_md_ctx_t* erl_md_ctx)
{
    ERL_NIF_TERM ret;
    EVP_MD_CTX* ctx;

    // Make a copy so we do not change the context
    ctx = EVP_MD_CTX_create();
    if(!EVP_MD_CTX_copy_ex(ctx, erl_md_ctx->ctx)) {
        return atom_error;
    }

    if(!EVP_DigestFinal_ex(
                ctx,
                enif_make_new_binary(env, EVP_MD_CTX_size(ctx), &ret), NULL)) {
        ret = atom_error;
    }

    EVP_MD_CTX_destroy(ctx);

    return ret;
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
            (ErlNifResourceDtor*)evp_md_destructor,
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
