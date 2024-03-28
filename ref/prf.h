#ifndef SPX_PRF_H
#define SPX_PRF_H

#include <stdint.h>
#include "params.h"

/*
 * This initializes the prf structures in the ctx.  This is called early on
 * in the signing process (after we've hashed the message) and the key
 * generation process
 */
#define initialize_prf_key SPX_NAMESPACE(initialize_prf_key)
void initialize_prf_key(uint64_t tree, uint32_t idx_leaf,
			spx_ctx *ctx);

/*
 * This evaluates a single node in a PRF tree.
 * If you need more than one, consider using a PRF iterator (below)
 */
#define eval_single_prf_leaf SPX_NAMESPACE(eval_single_prf_leaf)
void eval_single_prf_leaf( unsigned char *output, const unsigned char *root,
	                      unsigned i, unsigned n, const spx_ctx *ctx,
			      uint32_t addr[8] );

/*
 * The state structure for a PRF iterator (which generates the consecutive
 * keys for a PRF tree
 */
struct prf_iter {
    unsigned num_node;
    unsigned min_node;
    int stop_node;
    int cur_node;
    unsigned node[12];
    int count[12];
    const spx_ctx *ctx;
    uint32_t addr[8];
    unsigned char node_value[12][3*SPX_N];
};

/* Initialize the above structure to go through the tree leaves */
#define initialize_prf_iter SPX_NAMESPACE(initialize_prf_iter)
void initialize_prf_iter( struct prf_iter *iter, int n, int stop_value,
                          const unsigned char *seed, const spx_ctx *ctx,
			  const uint32_t addr[8] );

/* Generate the next tree leaf */
#define next_prf_iter SPX_NAMESPACE(next_prf_iter)
int next_prf_iter( unsigned char *output, struct prf_iter *iter );

#endif
