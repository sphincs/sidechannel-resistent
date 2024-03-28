#include <stdint.h>

/*
 * This computes the Keccak permutation on a thresholded input state
 * It outputs the resulting state either as the thresholded or unthresholded
 * state
 */
void do_threshold_keccak_permutation( const uint64_t *instate,
	                                    uint64_t *outstate1,
				            int output_threshold );
