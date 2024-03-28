#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "fors.h"
#include "utils.h"
#include "utilsx1.h"
#include "hash.h"
#include "thash.h"
#include "address.h"
#include "prf.h"
#include "f-threshold.h"

static void fors_sk_to_leaf(unsigned char *leaf, const unsigned char *sk,
                            const spx_ctx *ctx,
                            uint32_t fors_leaf_addr[8])
{
    thash(leaf, sk, 1, ctx, fors_leaf_addr);
}

struct fors_gen_leaf_info {
    uint32_t leaf_addrx[8];
    struct prf_iter *iter;  /* The iterator that will give us the next */
                            /* PRF value */
};

static void fors_gen_leafx1(unsigned char *leaf,
                            const spx_ctx *ctx,
                            uint32_t addr_idx, void *info)
{
    struct fors_gen_leaf_info *fors_info = info;
    uint32_t *fors_leaf_addr = fors_info->leaf_addrx;
    unsigned char temp_buffer[3*SPX_N];
    uint64_t state[3*25];

    /* Only set the parts that the caller doesn't set */
    set_tree_index(fors_leaf_addr, addr_idx);

    /* Get the PRF output */
    next_prf_iter( temp_buffer, fors_info->iter );

    /* Perform the F function.  We use our fancy threshold */
    /* implementation; the input is blinded, the output is not (because */
    /* it's safe if the attacker learns the F output here) */
    set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSTREE);
    unsigned k = set_up_f_block( state, temp_buffer, ctx, fors_leaf_addr );

    f_transform( state, 0 );  /* 0 -> unblind the result */

    /* And copy out the result */
    untransform_f( leaf, &state[k] );
}

/**
 * Interprets m as SPX_FORS_HEIGHT-bit unsigned integers.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 * Assumes indices has space for SPX_FORS_TREES integers.
 */
static void message_to_indices(uint32_t *indices, const unsigned char *m)
{
    unsigned int i, j;
    unsigned int offset = 0;

    for (i = 0; i < SPX_FORS_TREES; i++) {
        indices[i] = 0;
        for (j = 0; j < SPX_FORS_HEIGHT; j++) {
            indices[i] ^= ((unsigned)(m[offset >> 3] >> (~offset & 0x7)) & 1u) << (SPX_FORS_HEIGHT-1-j);
            offset++;
        }
    }
}

/**
 * Signs a message m, deriving the secret key from sk_seed and the FTS address.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 */
void fors_sign(unsigned char *sig, unsigned char *pk,
               const unsigned char *m,
               const spx_ctx *ctx,
               const uint32_t fors_addr[8])
{
    uint32_t indices[SPX_FORS_TREES];
    unsigned char roots[SPX_FORS_TREES * SPX_N];
    uint32_t fors_tree_addr[8] = {0};
    struct fors_gen_leaf_info fors_info = {0};
    uint32_t *fors_leaf_addr = fors_info.leaf_addrx;
    uint32_t fors_pk_addr[8] = {0};
    uint32_t idx_offset;
    unsigned int i;
    uint32_t top_prf_addr[8] = {0};
    struct prf_iter prf_iter;

    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_leaf_addr, fors_addr);

    copy_keypair_addr(fors_pk_addr, fors_addr);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    /*
     * Set up the iterator that we'll use to generate all the FORS
     * secret values
     */
    copy_keypair_addr(top_prf_addr, fors_addr);
    set_type(top_prf_addr, SPX_ADDR_TYPE_PRF_FORS);
    unsigned count_fors_leaves_per_tree = 1 << SPX_FORS_HEIGHT;
    unsigned count_fors_leaves = SPX_FORS_TREES * count_fors_leaves_per_tree;
    initialize_prf_iter( &prf_iter,
		          (int)count_fors_leaves,
		          (int)count_fors_leaves,
                          ctx->fors_seed, ctx, top_prf_addr );

    message_to_indices(indices, m);

    for (i = 0; i < SPX_FORS_TREES; i++) {
	unsigned char temp_buffer[3*SPX_N];

        idx_offset = i * (1 << SPX_FORS_HEIGHT);

        set_tree_height(fors_tree_addr, 0);
        set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSPRF);
        set_tree_index(fors_tree_addr, i);

        /* Include the secret key part that produces the selected leaf node */
        eval_single_prf_leaf( temp_buffer, ctx->fors_seed,
		              indices[i] + i*count_fors_leaves_per_tree,
		              count_fors_leaves, ctx, top_prf_addr );
	/* eval_single_prf_leaf gives us the value in threshold format */
        /* Convert it into the format that the verifier will expect to see */
	/* in the signature */
	for (int j=0; j<SPX_N; j++) {
	    sig[j] = temp_buffer[j] ^ temp_buffer[j + SPX_N] ^ temp_buffer[j + 2*SPX_N];
	}
        sig += SPX_N;

	/* And pass the iterator that will produce all the PRF values */
        fors_info.iter = &prf_iter;

        set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
        set_tree_index(fors_tree_addr, indices[i] + idx_offset);

        /* Compute the authentication path for this leaf node. */
        treehashx1(roots + i*SPX_N, sig, ctx,
                 indices[i], idx_offset, SPX_FORS_HEIGHT, fors_gen_leafx1,
                 fors_tree_addr, &fors_info);

        sig += SPX_N * SPX_FORS_HEIGHT;
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    thash(pk, roots, SPX_FORS_TREES, ctx, fors_pk_addr);
}

/**
 * Derives the FORS public key from a signature.
 * This can be used for verification by comparing to a known public key, or to
 * subsequently verify a signature on the derived public key. The latter is the
 * typical use-case when used as an FTS below an OTS in a hypertree.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 */
void fors_pk_from_sig(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *m,
                      const spx_ctx* ctx,
                      const uint32_t fors_addr[8])
{
    uint32_t indices[SPX_FORS_TREES];
    unsigned char roots[SPX_FORS_TREES * SPX_N];
    unsigned char leaf[SPX_N];
    uint32_t fors_tree_addr[8] = {0};
    uint32_t fors_pk_addr[8] = {0};
    uint32_t idx_offset;
    unsigned int i;

    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_pk_addr, fors_addr);

    set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices(indices, m);

    for (i = 0; i < SPX_FORS_TREES; i++) {
        idx_offset = i * (1 << SPX_FORS_HEIGHT);

        set_tree_height(fors_tree_addr, 0);
        set_tree_index(fors_tree_addr, indices[i] + idx_offset);

        /* Derive the leaf from the included secret key part. */
        fors_sk_to_leaf(leaf, sig, ctx, fors_tree_addr);
        sig += SPX_N;

        /* Derive the corresponding root node of this tree. */
        compute_root(roots + i*SPX_N, leaf, indices[i], idx_offset,
                     sig, SPX_FORS_HEIGHT, ctx, fors_tree_addr);
        sig += SPX_N * SPX_FORS_HEIGHT;
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    thash(pk, roots, SPX_FORS_TREES, ctx, fors_pk_addr);
}
