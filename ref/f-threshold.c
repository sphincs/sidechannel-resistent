#include <stdint.h>
#include <string.h>

#include "utils.h"
#include "address.h"
#include "params.h"
#include "f-threshold.h"
#include "fips202-threshold.h"

/*
 * This is the code that implements the F function
 * It is nontrivial because we use our threshold implementation of Keccak
 * (which only does the permutation piece of SHAKE256; we get to implement
 * the rest of the details here).
 *
 * When we evaluate F, the length of the inputs and outputs are always
 * smaller than the rate; hence SHAKE-256 can be implemented by 'filling
 * in the initial state', 'performing a single permuation', and 'extracting
 * the first n bytes of the final permutation'.  We exploit that.
 *
 * In addition, our WOTS code does chained F evaluations; we keep the
 * running value in uint64_t format, rather than converting it into a
 * byte string and then back into uint64_t format for every iteration.
 * In addition, we set up the constant (and mostly constant) parts of
 * the initial state once at the beginning of the Winternitz chain, rather
 * than reinitializing those values every single time; we refer to this
 * initial state as the 'chain state'.
 */

/* The size of a hash (in uint64_t's) - we use it a lot */
#define N (SPX_N/8)

/* This is the offset that the running hash lives (in uint64_t's) */
/* That is, where the hash from the previous PRF or F function is */
#define OFFSET_HASH (N + 32/8)

/*
 * Convert a bytestring into a uint64_t format (which is what our Keccak
 * permutation actually uses)
 */
static void transform_f( uint64_t *output, const void *input, int num_bytes )
{
    const unsigned char *in = input;
    for (; num_bytes > 0; num_bytes -= 8) {
	uint64_t val = 0;
	for (int i=7; i>=0; i--) {
	    val = (val << 8) | in[i];
	}
	*output++ = val;
	in += 8;
    }
}

/*
 * Convert the uint64_t encoded value (what our Keccak implementation uses)
 * into a byte string representation (which is what everything else wants)
 * This converts SPX_N bytes
 */
void untransform_f( unsigned char *result, const uint64_t *encoded )
{
    for (int i=0; i<SPX_N; i+=8) {
	uint64_t val = *encoded++;
	for (int j=0; j<8; j++) {
	    result[j] = (unsigned)val & 0xff;
	    val >>= 8;
	}
	result += 8;
    }
}

/*
 * This sets up the threshold chain state
 * This returns the offset of the running hash within the chain state
 */
unsigned set_up_f_block( uint64_t *chain_state,
	                 const unsigned char *prf_output,
                         const spx_ctx *ctx, uint32_t leaf_addr[8] )
{

    /* Zero out all parts of the chain state (except for the initial part */
    /* we'll fill in) */
    memset( &chain_state[ OFFSET_HASH + N ], 0,
		          8*(3*25 - (OFFSET_HASH + N)) );

    /* Fill in the public seed (PK.seed) */
    transform_f( &chain_state[0], ctx->pub_seed, SPX_N );

    /* Fill in the ADRS structure */
    transform_f( &chain_state[N], leaf_addr, 32 );

    /* Fill in the initial hash values (in threshold format) */
    transform_f( &chain_state[N+32/8],      &prf_output[0*SPX_N], SPX_N );
    transform_f( &chain_state[N+32/8 + 25], &prf_output[1*SPX_N], SPX_N );
    transform_f( &chain_state[N+32/8 + 50], &prf_output[2*SPX_N], SPX_N );

    /* Fill in the SHAKE256 padding (which we have to do ourselves, the */
    /* threshold SHAKE implementation won't do it for us) */
    chain_state[N+32/8+N] = 0x1f;    /* Marker at the end of the data */
    chain_state[16] ^= (1ULL << 63); /* Marker at the end of the rate */

    return OFFSET_HASH;
}

/*
 * This reaches into the hash address field of the ADRS structure within the
 * chain state, and increments it (setting things up for the next F evaluation)
 * Yes, it's ugly - however, it is efficient
 */
void increment_hash_addr_in_chain_state( uint64_t *chain_state )
{
    chain_state[N + (SPX_OFFSET_HASH_ADDR/8)] +=
	                              1ULL << (8*(SPX_OFFSET_HASH_ADDR%8));
}

/*
 * This actually performs the F function on the chain state, placing the
 * result back into chain state
 * If keep_blinded is 1, the resulting state will still be blinded.
 * If 0, this will unblind it
 */
void f_transform( uint64_t *chain_state, int keep_blinded )
{
    uint64_t output_state[3 * 25];

    /* We've already set up the initial state; call our fancy threshold
     * Keccak implementation to get the F output
     */
    do_threshold_keccak_permutation( chain_state, output_state, keep_blinded );

    /* The result of the SHAKE256 operation are just the first SPX_N words */
    /* of output state */

    /* Now, copy the resulting state back into the chain state */
    memcpy( &chain_state[OFFSET_HASH], &output_state[0], SPX_N );
    if (keep_blinded) {
	/* If we're still blinded, we'll need to copy the other shares also */
        memcpy( &chain_state[OFFSET_HASH + 25], &output_state[25], SPX_N );
        memcpy( &chain_state[OFFSET_HASH + 50], &output_state[50], SPX_N );
    }
}

