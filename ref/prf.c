#include <stddef.h>
#include <string.h>
#include <stdint.h>

#include "api.h"
#include "params.h"
#include "context.h"
#include "prf.h"
#include "address.h"
#include "hash.h"

/*
 * This implements the code neededfor the Threshold Resistant PRF function
 * (which is an alternative to the PRF function defined in LHS-DSA)
 * The actual PRF implementation (which relies on this code) are in the
 * WOTS and FORS specific files
 */

/*
 * This evaluates the tree function for one particular leaf
 * root - The root value to start with
 * i - Leaf index
 * n - Total number of leaves
 * addr - The address structure to use.  It is assumed that all the fields
 *        (except for PRF index) are set up; this will be modified in place
 * output - Where to place the output
 *
 * This assumes that 1 < n < 2^19
 */
void eval_single_prf_leaf( unsigned char *output, const unsigned char *root,
	                   unsigned i, unsigned n, const spx_ctx *ctx,
			   uint32_t addr[8] )
{
    /*
     * Internally, we track things by node number (which includes the internal
     * nodes); convert i from the external representation to our internal one
     */
    i += (n+1)/3;

    /*
     * Compute the path through the 4-way tree (in bottom-up order)
     */
    unsigned stack[10];  /* Large enough for n=2^19 */
    int sp = 0;
    while (i > 0) {
	stack[sp++] = i;
	i = (i-1)/4;
    }

    /*
     * Now, step through the tree (in top-down order)
     */
    const unsigned char *prev_node = root;
    for (int j=sp-1; j>=0; j--) {
	set_prf_index( addr, stack[j] );
	prf_hash_function( output, ctx, addr, prev_node );
	prev_node = output;
    }
}

/*
 * This is the code to implement the 'PRF iterator', which goes through
 * all the external nodes of a PRF tree in succession.
 * This current logic generates the PRF nodes in order (that is, node 0 is
 * generated first, then node 1, etc).  Actually, it would be slightly more
 * efficient to generate the nodes from left to right in the tree; however
 * that's a different order (unless the number of external nodes 'n' happens
 * to be a power of 4).  However, the efficiency delta is small, and the
 * rest of the code wants nodes starting with 0 (and I decided it wasn't
 * worth it to reorganize the code for that small bit of efficiency)
 */

/*
 * Initialize a prf_iter structure to the beginning of a PRF tree
 * n - Number of external nodes of the tree
 * seed - The root value
 * ctx - The Sphincs+ context to use
 * addr - The address to use.  Note that this saves the value, and so the
 *        caller is free to modify it while the iteration is taking place
 */
void initialize_prf_iter( struct prf_iter *it, int n, int stop_node,
                          const unsigned char *seed, const spx_ctx *ctx,
			  const uint32_t addr[8] )
{
    unsigned min_node;
    it->min_node = min_node = (unsigned)(n+1)/3;
    it->stop_node = stop_node + (int)min_node;
    it->ctx = ctx;
    memcpy( it->addr, addr, 8 * sizeof(uint32_t) );

    /* Compute the path to the first node (in bottom up order) */
    unsigned stack[10];
    int sp = 0;
    unsigned i = min_node;
    while (i > 0) {
	stack[sp++] = i;
	i = (i-1)/4;
    }

    /* Fill in the top level node (the root) */
    it->node[0] = 0;
    it->count[0] = 0;
    memcpy( it->node_value[0], seed, 3*SPX_N );

    /* Compute the entries on the path to the first node */
    for (int j=sp-1, k=1; j>=0; j--, k++) {
	it->node[k] = stack[j];
	it->count[k] = (stack[j]+3) % 4;
	set_prf_index( it->addr, stack[j] );
	prf_hash_function( it->node_value[k], it->ctx, it->addr, it->node_value[k-1] );
    }

    /* Initialize the 'where-we-are' parameters */
    it->num_node = (unsigned)(sp+1);
    it->cur_node = (int)min_node;
}

/*
 * Output the next node from the prf tree.  This returns the index being
 * output, or -1 if we've reached the end
 */
int next_prf_iter( unsigned char *output, struct prf_iter *it )
{
    if (it->cur_node == -1) return -1;  /* We hit the end */

        /* This leaf value was computed the last iteration */
    int ret_val = it->cur_node - (int)it->min_node;
    memcpy( output, it->node_value[ it->num_node-1 ], 3*SPX_N );

    if (it->cur_node == it->stop_node) {
	    /* We're at the end - say so next time */
	it->cur_node = -1;
    } else {
	    /* There's another node after this - compute it */

	    /* We'll increment the value stored in the count array */
	    /* Search for the digit where the carry propogation stops */
	unsigned i = it->num_node;
	for (;;) {
	    if (i == 0) break;
	    i--;
            if (it->count[i] < 3) {
		break;
	    }
	}
	/* The first non-3 digit was digit 'i' */
	if (i > 0) {
		/* Increment that digit */
	    it->count[i] += 1;
	    it->node[i] += 1;
	    set_prf_index( it->addr, it->node[i] );
	    prf_hash_function( it->node_value[i], it->ctx, it->addr, it->node_value[i-1] );
	} else {
		/* It stops at digit 0. This is the point where the depth */
		/* of the external nodes increases by one */
		/* We need to 'wrap around'; we increase the number of */
		/* digits by 1, and reset all the digits to 0 (which the */
		/* below code will do) */
	    it->num_node += 1;
	}

            /* And reset all the lower digits to 0 */
	i++;
	for (; i < it->num_node; i++) {
	    it->count[i] = 0;
	    it->node[i] = 4*it->node[i-1] + 1;
	    set_prf_index( it->addr, it->node[i] );
	    prf_hash_function( it->node_value[i], it->ctx, it->addr, it->node_value[i-1] );
	}
    }

    /* And we've set things up for the next node */
    it->cur_node++;

    return ret_val;
}

/*
 * This returns val shifted right by shift bits
 *
 * This is here because some parameter sets will have a shift of 64 for the
 * top Merkle tree and C has undefined behavior for 'val >> 64'
 */
static uint64_t shiftr( uint64_t val, int shift )
{
    if (shift >= 64) {
	return 0;
    } else {
	return val >> shift;
    }
}

/*
 * Compute the keys used for the Merkle and FORS trees used during this
 * signature
 * We do this once early on in the signature process (once we have learned
 * which Merkle leaf we will use)
 */
void initialize_prf_key(uint64_t tree, uint32_t idx_leaf, spx_ctx *ctx)
{
    const unsigned char *parent_seed = ctx->sk_seed;

    /*
     * The seed for the top Merkle tree is the ultimate root key
     */
    memcpy( ctx->merkle_key[SPX_D-1], ctx->sk_seed, 3 * SPX_N );

    /*
     * Go through each Merkle tree, and generate the root key for it (and the
     * seed for the next Merkle tree
     */
    for (int level=SPX_D-1, tree_shift = SPX_FULL_HEIGHT - SPX_TREE_HEIGHT;
		       level>=0; level--, tree_shift -= SPX_TREE_HEIGHT) {
        uint32_t addr[8] = {0};
	unsigned char *child_seed;

	if (level == 0) {
	    /* For the bottom most Merkle tree, the seed we generate is */
	    /* for the FORS */
	    child_seed = ctx->fors_seed;
	} else {
	    /* Otherwise, it's for the next Merkle tree below us */
	    child_seed = ctx->merkle_key[level-1];
	}


	/* Generate the prf seed for the next level */
	set_type( addr, SPX_ADDR_TYPE_PRF_MERKLE );
        set_layer_addr(addr, (uint32_t)level);
        set_tree_addr(addr, shiftr(tree, tree_shift) );
	uint32_t leaf;
	if (level == 0) {
            leaf = idx_leaf;
	} else {
            leaf = (uint32_t)(tree >> (tree_shift - SPX_TREE_HEIGHT));
	    leaf &= (1 << SPX_TREE_HEIGHT) - 1;
	}
        eval_single_prf_leaf( child_seed, parent_seed,
			   /* The external node that we use for the next seed buffer */
		       leaf + SPX_WOTS_LEN * (1 << SPX_TREE_HEIGHT),
		           /* Number of external nodes in this PRF tree */
		       (SPX_WOTS_LEN+1) * (1 << SPX_TREE_HEIGHT),
		       ctx, addr );
        parent_seed = child_seed;
    }
}
