#if !defined( F_THRESHOLD_H_ )

#include <stdint.h>
#include "context.h"

/*
 * This sets up the thresfold chain state
 * This returns the offset of the running hash within the chain state
 */
unsigned set_up_f_block( uint64_t *chain_state,
	                 const unsigned char *prf_output,
                         const spx_ctx *ctx, uint32_t addr[8] );

/*
 * Convert the uint64_t encoded value into a byte string representation
 * This converts SPX_N bytes
 */
void untransform_f( unsigned char *result, const uint64_t *encoded );

/*
 * Increment the running hash address in the chain state to k
 */
void increment_hash_addr_in_chain_state( uint64_t *chain_state );

/*
 * Perform the f operation on the chain state, placing the result back
 * into the chain state
 * If keep_blinded == 0, this will unblind the chain state
 */
void f_transform( uint64_t *chain_state, int keep_blinded );

#endif
