#ifndef SPX_CONTEXT_H
#define SPX_CONTEXT_H

#include <stdint.h>

#include "params.h"

typedef struct {
    uint8_t pub_seed[SPX_N];
    uint8_t sk_seed[3*SPX_N];

    /* This array contains the keys used to derive the WOTS prf values
       for each Merkle tree
       Indexed so that the bottom tree is index 0, the top tree is index
       SPX_D-1 */
    unsigned char merkle_key[SPX_D][3*SPX_N];

    /* The seed we use to derive the FORS prf values */
    unsigned char fors_seed[3*SPX_N];

#ifdef SPX_SHA2
    // sha256 state that absorbed pub_seed
    uint8_t state_seeded[40];

# if SPX_SHA512
    // sha512 state that absorbed pub_seed
    uint8_t state_seeded_512[72];
# endif
#endif

#ifdef SPX_HARAKA
    uint64_t tweaked512_rc64[10][8];
    uint32_t tweaked256_rc32[10][8];
#endif
} spx_ctx;

#endif
