#include "ezstd_nif.h"
#include "nif_utils.h"
#include "macros.h"

#include <stdlib.h>
#include <zstd.h>

const char kAtomError[] = "error";
const char kAtomBadArg[] = "badarg";

struct atoms ATOMS;

ErlNifResourceType *COMPRESS_DICTIONARY_RES_TYPE;
ErlNifResourceType *DECOMPRESS_DICTIONARY_RES_TYPE;
ErlNifResourceType *STREAM_COMPRESS_RES_TYPE;
ErlNifResourceType *STREAM_COMPRESS_STORAGE_RES_TYPE;

struct stream_compress_storage {
    ZSTD_CStream *stream;
    ErlNifBinary bin;
    size_t pos;
    unsigned capacity_step;
};


void zstd_nif_compress_dictionary_destructor(ErlNifEnv *env, void *res) {
    UNUSED(env);
    ZSTD_CDict** dict_resource = (ZSTD_CDict**)res;
    ZSTD_freeCDict(*dict_resource);  
}

void zstd_nif_decompress_dictionary_destructor(ErlNifEnv *env, void *res) {
    UNUSED(env);
    ZSTD_DDict** dict_resource = (ZSTD_DDict**)res;
    ZSTD_freeDDict(*dict_resource);
}

void zstd_nif_stream_compress_destructor(ErlNifEnv *env, void *res) {
    UNUSED(env);
    ZSTD_CStream** stream_resource = (ZSTD_CStream**)res;
    ZSTD_freeCStream(*stream_resource);
}

void zstd_nif_stream_compress_storage_destructor(ErlNifEnv *env, void *res) {
    UNUSED(env);
    struct stream_compress_storage *s = (struct stream_compress_storage*)res;
    if (s->stream) ZSTD_freeCStream(s->stream);
    if (s->bin.size > 0) enif_release_binary(&s->bin);
}

int on_nif_load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info) {
    UNUSED(load_info);
    UNUSED(priv_data);

    ATOMS.atomError = make_atom(env, kAtomError);
    ATOMS.atomBadArg = make_atom(env, kAtomBadArg);
    ATOMS.atomOk = make_atom(env, "ok");
    ATOMS.atomFlush = make_atom(env, "flush");

    ErlNifResourceFlags flags = ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER;
    COMPRESS_DICTIONARY_RES_TYPE = enif_open_resource_type(env, NULL, "ZStandard.CompressDictionary", zstd_nif_compress_dictionary_destructor, flags, NULL);
    DECOMPRESS_DICTIONARY_RES_TYPE = enif_open_resource_type(env, NULL, "ZStandard.DecompressDictionary", zstd_nif_decompress_dictionary_destructor, flags, NULL);
    STREAM_COMPRESS_RES_TYPE = enif_open_resource_type(env, NULL, "ZStandard.StreamCompress", zstd_nif_stream_compress_destructor, flags, NULL);
    STREAM_COMPRESS_STORAGE_RES_TYPE = enif_open_resource_type(env, NULL, "ZStandard.StreamStorage", zstd_nif_stream_compress_storage_destructor, flags, NULL);

    return 0;
}

static ERL_NIF_TERM zstd_nif_get_dict_id_from_cdict(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    UNUSED(argc);
    ZSTD_CDict** dict_resource;

    if(!enif_get_resource(env, argv[0], COMPRESS_DICTIONARY_RES_TYPE, (void**)(&dict_resource))) {
            return make_badarg(env);
    }

    unsigned result = ZSTD_getDictID_fromCDict(*dict_resource);
    return enif_make_uint(env, result);
}

static ERL_NIF_TERM zstd_nif_get_dict_id_from_ddict(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    UNUSED(argc);
    ZSTD_DDict** dict_resource;

    if(!enif_get_resource(env, argv[0], DECOMPRESS_DICTIONARY_RES_TYPE, (void**)(&dict_resource))) {
            return make_badarg(env);
    }

    unsigned result = ZSTD_getDictID_fromDDict(*dict_resource);
    return enif_make_uint(env, result);
} 

static ERL_NIF_TERM zstd_nif_compress_using_cdict(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    UNUSED(argc);
    ErlNifBinary bin, out_bin;
    ZSTD_CDict** dict_resource;
    ERL_NIF_TERM ret;

    if (!enif_inspect_binary(env, argv[0], &bin) ||
       !enif_get_resource(env, argv[1], COMPRESS_DICTIONARY_RES_TYPE, (void**)(&dict_resource))) {
            return make_badarg(env);
    }

    size_t out_buffer_size = ZSTD_compressBound(bin.size);
    if (!enif_alloc_binary(out_buffer_size, &out_bin)) {
        return make_error(env, "failed to alloc");
    }
    ZSTD_CCtx* ctx = ZSTD_createCCtx();
    if (!ctx) {
        return make_error(env, "failed to alloc");
    }

    size_t compressed_size = ZSTD_compress_usingCDict(ctx, out_bin.data, out_buffer_size, bin.data, bin.size, *dict_resource);

    if(ZSTD_isError(compressed_size)) {
        return make_error(env, "failed to compress");
    }

    if(!enif_realloc_binary(&out_bin, compressed_size)) {
        ret = make_error(env, "failed to alloc");
    } else {
        ret = enif_make_binary(env, &out_bin);
    }

    ZSTD_freeCCtx(ctx);
    return ret;
}

static ERL_NIF_TERM zstd_nif_decompress_using_ddict(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    UNUSED(argc);
    ErlNifBinary bin;
    ZSTD_DDict** dict_resource;
    ERL_NIF_TERM ret;

    if(!enif_inspect_binary(env, argv[0], &bin) ||
       !enif_get_resource(env, argv[1], DECOMPRESS_DICTIONARY_RES_TYPE, (void**)&dict_resource)) {
            return make_badarg(env);
    }

    ZSTD_DCtx *ctx = ZSTD_createDCtx();
    if (!ctx) {
      return make_error(env, "failed to alloc");
    }

    uint64_t uncompressed_size = ZSTD_getFrameContentSize(bin.data, bin.size);

    if (uncompressed_size == ZSTD_CONTENTSIZE_UNKNOWN) {
        ret = make_error(env, "failed to decompress: ZSTD_CONTENTSIZE_UNKNOWN");
        goto out;
    }

    if (uncompressed_size == ZSTD_CONTENTSIZE_ERROR) {
        ret = make_error(env, "failed to decompress: ZSTD_CONTENTSIZE_ERROR");
        goto out;
    }

    ERL_NIF_TERM out_term;
    uint8_t *destination_buffer = enif_make_new_binary(env, uncompressed_size, &out_term);

    size_t actual_decompressed_size = ZSTD_decompress_usingDDict(ctx, destination_buffer, uncompressed_size, bin.data, bin.size, *dict_resource);

    if (actual_decompressed_size != uncompressed_size) {
        ret = make_error(env, "failed to decompress");
        goto out;
    }

    ret = out_term;

out:
    ZSTD_freeDCtx(ctx);
    return ret;
}

static ERL_NIF_TERM zstd_nif_create_cdict(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    UNUSED(argc);

    ErlNifBinary bin;
    int compression_level;
   

    if(!enif_inspect_binary(env, argv[0], &bin) ||
       !enif_get_int(env, argv[1], &compression_level) ||
       compression_level > ZSTD_maxCLevel() || 
       compression_level < ZSTD_minCLevel()) {
            return make_badarg(env);
    }


    ZSTD_CDict* dict = ZSTD_createCDict(bin.data, bin.size, compression_level);
    if (!dict) {
      return make_error(env, "failed to create cdict");
    }

    /* enif_alloc_resource cannot fail: https://github.com/erlang/otp/blob/df484d244705180def80fae22cba747d3e5bfdb1/erts/emulator/beam/erl_nif.c#L3029 */
    ZSTD_CDict** resource = (ZSTD_CDict**)enif_alloc_resource(COMPRESS_DICTIONARY_RES_TYPE, sizeof(ZSTD_CDict*));

    *resource = dict;

    ERL_NIF_TERM result = enif_make_resource(env, resource);

    enif_release_resource(resource);
    return result;
}

static ERL_NIF_TERM zstd_nif_create_ddict(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    UNUSED(argc);

    ErlNifBinary bin;


    if(!enif_inspect_binary(env, argv[0], &bin)) {
            return make_badarg(env);
    }


    ZSTD_DDict* dict = ZSTD_createDDict(bin.data, bin.size);

    if (!dict) {
      return make_error(env, "failed to create cdict");
    }

    /* enif_alloc_resource cannot fail */
    ZSTD_DDict** resource = (ZSTD_DDict**)enif_alloc_resource(DECOMPRESS_DICTIONARY_RES_TYPE, sizeof(ZSTD_DDict*));

    *resource = dict;

    ERL_NIF_TERM result = enif_make_resource(env, resource);

    enif_release_resource(resource);
    return result;
}

static ERL_NIF_TERM zstd_nif_compress(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    UNUSED(argc);

    ErlNifBinary bin, out_bin;
    int compression_level;

    if (!enif_inspect_binary(env, argv[0], &bin) || 
       !enif_get_int(env, argv[1], &compression_level) || 
       compression_level > ZSTD_maxCLevel() ||
       compression_level < ZSTD_minCLevel())
            return make_badarg(env);

    size_t out_buffer_size = ZSTD_compressBound(bin.size);
    if (!enif_alloc_binary(out_buffer_size, &out_bin)) {
        return make_error(env, "failed to alloc");
    }
  
    size_t compressed_size = ZSTD_compress(out_bin.data, out_buffer_size, bin.data, bin.size, compression_level);

    if (ZSTD_isError(compressed_size))
        return make_error(env, "failed to compress");    
        
    if (!enif_realloc_binary(&out_bin, compressed_size))
        return make_error(env, "failed to alloc");

    return enif_make_binary(env, &out_bin);
}

static ERL_NIF_TERM zstd_nif_get_dict_id_from_frame(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    UNUSED(argc);

  
    ErlNifBinary bin;

    if(!enif_inspect_binary(env, argv[0], &bin)) {
            return make_badarg(env);
    }

    unsigned result = ZSTD_getDictID_fromFrame(bin.data, bin.size);
    return enif_make_uint(env, result);
}

static ERL_NIF_TERM zstd_nif_decompress(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    UNUSED(argc);

    ErlNifBinary bin;

    if (!enif_inspect_binary(env, argv[0], &bin))
        return make_badarg(env);

    uint64_t uncompressed_size = ZSTD_getFrameContentSize(bin.data, bin.size);

    if (uncompressed_size == ZSTD_CONTENTSIZE_UNKNOWN) {
        return make_error(env, "failed to decompress: ZSTD_CONTENTSIZE_UNKNOWN");
    }

    if (uncompressed_size == ZSTD_CONTENTSIZE_ERROR) {
        return make_error(env, "failed to decompress: ZSTD_CONTENTSIZE_ERROR");
    }

    ERL_NIF_TERM out_term;
    uint8_t *destination_buffer = enif_make_new_binary(env, uncompressed_size, &out_term);

    if (ZSTD_decompress(destination_buffer, uncompressed_size, bin.data, bin.size) != uncompressed_size) {
        return make_error(env, "failed to decompress");
    }

    return out_term;
}

static ERL_NIF_TERM zstd_nif_create_compress_stream(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 1)
        return make_badarg(env);
    
    int compression_level;

    ZSTD_CStream *ctx = ZSTD_createCStream();

    if(!enif_get_int(env, argv[0], &compression_level) ||
       compression_level > ZSTD_maxCLevel() || 
       compression_level < ZSTD_minCLevel()) {
            return make_badarg(env);
    }
    if (!ZSTD_CCtx_setParameter(ctx, ZSTD_c_compressionLevel, compression_level)) {
        ZSTD_freeCStream(ctx);
        return make_error(env, "failed set param");
    }
    if (!ZSTD_CCtx_setParameter(ctx, ZSTD_c_checksumFlag, 1)) {
        ZSTD_freeCStream(ctx);
        return make_error(env, "failed set param");
    }

    ZSTD_CStream** resource = (ZSTD_CStream**)enif_alloc_resource(STREAM_COMPRESS_RES_TYPE, sizeof(ZSTD_CStream*));
    *resource = ctx;

    ERL_NIF_TERM result = enif_make_tuple2(env, ATOMS.atomOk, enif_make_resource(env, resource));

    enif_release_resource(resource);
    return result;
}

static ERL_NIF_TERM zstd_nif_compress_stream(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 2)
        return make_badarg(env);

    ZSTD_CStream **ctx = NULL;
    ErlNifBinary bin, out_bin;

    if (!enif_get_resource(env, argv[0], STREAM_COMPRESS_RES_TYPE, (void**)(&ctx)))
        return make_badarg(env);

    if (argv[1] != ATOMS.atomFlush && !enif_inspect_binary(env, argv[1], &bin))
        return make_badarg(env);


    if (argv[1] != ATOMS.atomFlush && bin.size == 0) 
        return argv[1]; // compres 0 is 0

    if (argv[1] == ATOMS.atomFlush) {
        bin.size = 0;
        bin.data = NULL;
    }

    if (!enif_alloc_binary(ZSTD_CStreamOutSize(), &out_bin))
        return make_error(env, "failed to alloc");

    ZSTD_EndDirective const mode = bin.size == 0 ? ZSTD_e_end : ZSTD_e_continue;

    ZSTD_inBuffer input = {.src = bin.data, .size = bin.size, .pos = 0};
    ZSTD_outBuffer output = {.dst = out_bin.data, .size = out_bin.size, .pos = 0};
    int finished;
    do {
        size_t const remaining = ZSTD_compressStream2(*ctx, &output, &input, mode);
        if (output.pos == output.size) {
            if (!enif_realloc_binary(&out_bin, out_bin.size + ZSTD_CStreamOutSize())) {
                return make_error(env, "failed to alloc");
            }
            output.dst = out_bin.data;
            output.size = out_bin.size;
        }
        finished = bin.size == 0 ? (remaining == 0) : (input.pos == input.size);
    } while (!finished);

    if (!enif_realloc_binary(&out_bin, output.pos))
        return make_error(env, "failed to alloc");

    return enif_make_binary(env, &out_bin);
}

static ERL_NIF_TERM zstd_nif_decompress_stream_onepass(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 1)
        return make_badarg(env);

    ErlNifBinary bin, out_bin;
    ZSTD_DStream *ctx;
    ERL_NIF_TERM ret;

    if(!enif_inspect_binary(env, argv[0], &bin))
        return make_badarg(env);

    if (bin.size == 0) {
        ret = argv[0];
        goto out;
    }

    ctx = ZSTD_createDStream();

    if (!enif_alloc_binary(bin.size, &out_bin)) {
        ret = make_error(env, "failed to alloc");
        goto out;
    }

    ZSTD_outBuffer output = {.dst = out_bin.data, .pos = 0, .size = out_bin.size};
    ZSTD_inBuffer input = {.src = bin.data, .size = bin.size, .pos = 0};

    do {
        size_t ret = ZSTD_decompressStream(ctx, &output, &input);
        if (ZSTD_isError(ret)) {
            ret = make_error(env, "failed decompress");
            goto out;
        }
        if (output.size == output.pos && input.pos != input.size) {
            if (!enif_realloc_binary(&out_bin, out_bin.size + ZSTD_DStreamOutSize())) {
                ret = make_error(env, "failed to realloc");
                goto out;
            }
            output.dst = out_bin.data;
            output.size = out_bin.size;
        }
    } while (input.pos != input.size);

    if (out_bin.size > output.pos) {
        if (!enif_realloc_binary(&out_bin, output.pos)) {
            ret = make_error(env, "failed to realloc");
            goto out;
        }
    }

    ret = enif_make_binary(env, &out_bin);

out:
    ZSTD_freeDStream(ctx);
    return ret;
}


static ERL_NIF_TERM zstd_nif_create_compressed_storage(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 2)
        return make_badarg(env);

    int compression_level;
    unsigned capacity_step;
    ERL_NIF_TERM ret;

    ZSTD_CStream *ctx = ZSTD_createCStream();

    if(!enif_get_int(env, argv[0], &compression_level) ||
       compression_level > ZSTD_maxCLevel() || 
       compression_level < ZSTD_minCLevel()) {
            return make_badarg(env);
    }

    if (!enif_get_uint(env, argv[1], &capacity_step)) {
        return make_badarg(env);
    }


    if (!ZSTD_CCtx_setParameter(ctx, ZSTD_c_compressionLevel, compression_level)) {
        ZSTD_freeCStream(ctx);
        return make_error(env, "failed set param");
    }
    if (!ZSTD_CCtx_setParameter(ctx, ZSTD_c_checksumFlag, 1)) {
        ZSTD_freeCStream(ctx);
        return make_error(env, "failed set param");
    }

    struct stream_compress_storage *s = (struct stream_compress_storage *)enif_alloc_resource(STREAM_COMPRESS_STORAGE_RES_TYPE, sizeof(struct stream_compress_storage));
    s->bin.data = 0;
    s->bin.size = 0;
    s->pos = 0;
    s->stream = ctx;

    if (!enif_alloc_binary(capacity_step, &s->bin)) {
        s->bin.size = 0;
        ret = make_error(env, "failed to realloc");
        goto out;
    }

    ret = enif_make_tuple2(env, ATOMS.atomOk, enif_make_resource(env, s));

out:
    enif_release_resource(s);
    return ret;
}


static ERL_NIF_TERM zstd_nif_compress_to_storage(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 2)
        return make_badarg(env);

    struct stream_compress_storage *s;
    ErlNifBinary bin;

    if (!enif_get_resource(env, argv[0], STREAM_COMPRESS_STORAGE_RES_TYPE, (void**)&s))
        return make_badarg(env);

    if (!enif_inspect_binary(env, argv[1], &bin))
        return make_badarg(env);

    if (s->bin.size == 0)
        return make_error(env, "bad stream storage");

    if (s->pos == s->bin.size) {
        if (!enif_realloc_binary(&s->bin, s->bin.size + s->capacity_step))
            return make_error(env, "failed to realloc");
    }

    ZSTD_inBuffer input = {.src = bin.data, .size = bin.size, .pos = 0};
    ZSTD_outBuffer output = {.dst = s->bin.data, .size = s->bin.size, .pos = s->pos};
    do {
        /*size_t const remaining =*/ ZSTD_compressStream2(s->stream, &output, &input, ZSTD_e_continue);
        if (output.pos == output.size) {
            if (!enif_realloc_binary(&s->bin, s->bin.size + s->capacity_step)) {
                return make_error(env, "failed to realloc");
            }
            output.dst = s->bin.data;
            output.size = s->bin.size;
        }
    } while (input.pos != input.size);
    s->pos = output.pos;

    return enif_make_tuple2(env, ATOMS.atomOk, enif_make_uint(env, s->pos));
}

static ERL_NIF_TERM zstd_flush_compressed_storage(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 1)
        return make_badarg(env);

    struct stream_compress_storage *s;

    if (!enif_get_resource(env, argv[0], STREAM_COMPRESS_STORAGE_RES_TYPE, (void**)&s))
        return make_badarg(env);

    if (s->bin.size == 0)
        return make_error(env, "bad stream storage");

    ZSTD_inBuffer input = {.src = NULL, .size = 0, .pos = 0};
    ZSTD_outBuffer output = {.dst = s->bin.data, .size = s->bin.size, .pos = s->pos};
    int finished;
    do {
        size_t const remaining = ZSTD_compressStream2(s->stream, &output, &input, ZSTD_e_end);
        if (output.pos == output.size) {
            if (!enif_realloc_binary(&s->bin, s->bin.size + s->capacity_step)) {
                return make_error(env, "failed to realloc");
            }
            output.dst = s->bin.data;
            output.size = s->bin.size;
            finished = remaining == 0;
        }
    } while (!finished);
    s->pos = output.pos;

    if (!enif_realloc_binary(&s->bin, s->pos))
        return make_error(env, "failed to realloc");

    ERL_NIF_TERM bin_term = enif_make_binary(env, &s->bin);

    if (!enif_alloc_binary(s->bin.size, &s->bin))
        return make_error(env, "failed to alloc");

    s->pos = 0;
    return enif_make_tuple2(env, ATOMS.atomOk, bin_term);
}



static ErlNifFunc nif_funcs[] = {
    {"compress", 2, zstd_nif_compress, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"decompress", 1, zstd_nif_decompress, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"create_cdict", 2, zstd_nif_create_cdict},
    {"create_ddict", 1, zstd_nif_create_ddict},
    {"get_dict_id_from_ddict", 1, zstd_nif_get_dict_id_from_ddict},
    {"get_dict_id_from_cdict", 1, zstd_nif_get_dict_id_from_cdict},
    {"get_dict_id_from_frame", 1, zstd_nif_get_dict_id_from_frame},
    {"compress_using_cdict", 2, zstd_nif_compress_using_cdict, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"decompress_using_ddict", 2, zstd_nif_decompress_using_ddict, ERL_NIF_DIRTY_JOB_CPU_BOUND},

    {"create_compress_stream", 1, zstd_nif_create_compress_stream},
    {"compress_stream", 2, zstd_nif_compress_stream, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"decompress_stream_onepass", 1, zstd_nif_decompress_stream_onepass, ERL_NIF_DIRTY_JOB_CPU_BOUND},

    {"create_compressed_storage", 2, zstd_nif_create_compressed_storage},
    {"compress_to_storage", 2, zstd_nif_compress_to_storage, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"flush_compressed_storage", 1, zstd_flush_compressed_storage, ERL_NIF_DIRTY_JOB_CPU_BOUND}

};

ERL_NIF_INIT(ezstd_nif, nif_funcs, on_nif_load, NULL, NULL, NULL);
