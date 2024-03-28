#include <stdint.h>
#include <string.h>

#include "utils.h"
#include "hash.h"
#include "thash.h"
#include "wots.h"
#include "wotsx1.h"
#include "address.h"
#include "params.h"
#include "f-threshold.h"

/*
 * This generates a WOTS public key
 * It also generates the WOTS signature if leaf_info indicates
 * that we're signing with this WOTS key
 */
void wots_gen_leafx1(unsigned char *dest,
                   const spx_ctx *ctx,
                   uint32_t leaf_idx, void *v_info) {
    struct leaf_info_x1 *info = v_info;
    uint32_t *leaf_addr = info->leaf_addr;
    uint32_t *pk_addr = info->pk_addr;
    unsigned int i, k;
    unsigned char pk_buffer[ SPX_WOTS_BYTES ];
    unsigned char *buffer;
    uint32_t wots_k_mask;

    if (leaf_idx == info->wots_sign_leaf) {
        /* We're traversing the leaf that's signing; generate the WOTS */
        /* signature */
        wots_k_mask = 0;
    } else {
        /* Nope, we're just generating pk's; turn off the signature logic */
        wots_k_mask = (uint32_t)~0;
    }

    set_keypair_addr( leaf_addr, leaf_idx );
    set_keypair_addr( pk_addr, leaf_idx );

    for (i = 0, buffer = pk_buffer; i < SPX_WOTS_LEN; i++, buffer += SPX_N) {
        uint32_t wots_k = info->wots_steps[i] | wots_k_mask; /* Set wots_k to */
            /* the step if we're generating a signature, ~0 if we're not */
	uint64_t chain_state[3*25];
	int not_last_f;
	unsigned value_offset;
	unsigned char temp_buffer[3*SPX_N];

        /* Start with the secret seed; get it from our iterator */
        next_prf_iter( temp_buffer, &info->merkle_iter );

        set_type(leaf_addr, SPX_ADDR_TYPE_WOTS);
        set_chain_addr(leaf_addr, i);
        set_hash_addr(leaf_addr, 0);

	/* Fill in the values for the initial chain state */
	value_offset = set_up_f_block( chain_state, temp_buffer, ctx, leaf_addr );
	not_last_f = 1;  /* We will clear this when we compute the very */
	                 /* last F function for this chain */

        /* Iterate down the WOTS chain */
        for (k=0;; k++) {
            /* Check if this is the value that needs to be saved as a */
            /* part of the WOTS signature */
            if (k == wots_k) {
		uint64_t output_buffer[SPX_N/8];
		const uint64_t *value;
		if (not_last_f) {
		    /*
		     * We're in the middle of the chain; the value is still
		     * blinded.  Unblind it
		     */
		    for (unsigned m=0; m<SPX_N/8; m++) {
			output_buffer[m] = chain_state[m+value_offset] ^
				           chain_state[m+value_offset+25] ^
					   chain_state[m+value_offset+50];
		     }
		     value = output_buffer;
		} else {
                     /*
		      * We're at the top; the value was unblinded; no
		      * unblinding is necessary
		      */
		     value = &chain_state[value_offset];
		}
		/*
		 * The value is a series of uint64_t's; convert it into the
		 * byte string that must appear in the signature
		 */
		untransform_f( info->wots_sig + i * SPX_N, value );
            }

            /* Check if we hit the top of the chain */
	    if (!not_last_f) break;

	    /* Check if this is the last computation on the chain */
            if (k == SPX_WOTS_W - 2) not_last_f = 0;

            /* Iterate one step on the chain */
	    f_transform( chain_state, not_last_f );

	    /* And (for next time) increment the hash address field in the */
	    /* ADRS structure within the chain state */
            increment_hash_addr_in_chain_state(chain_state);
        }

	/*
	 * The chain state has the result as a series of uint64_t's
	 * Convert that back into a byte string, and place it into the
	 * buffer of top chain values
	 */
	untransform_f( buffer, &chain_state[value_offset] );
    }

    /* Do the final thash to generate the public keys */
    thash(dest, pk_buffer, SPX_WOTS_LEN, ctx, pk_addr);
}
