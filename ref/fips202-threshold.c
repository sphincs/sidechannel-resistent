/* Based on the public domain implementation in
 * crypto_hash/keccakc512/simple/ from http://bench.cr.yp.to/supercop.html
 * by Ronny Van Keer
 * and the public domain "TweetFips202" implementation
 * from https://twitter.com/tweetfips202
 * by Gilles Van Assche, Daniel J. Bernstein, and Peter Schwabe */

/*
 * This version implements a threshold version of the Keccak permutation.
 * The input is always in threshold format; the output can be either in
 * threshold or standard format.
 * Now, this starts of with a threshold implementation of the round function,
 * but switches to a standard format for most of the rounds.  We can do this
 * because of the size of the Keccak state (and the fact that, by the time
 * we switch to standard format, the state has been thoroughly mixed).
 * Then, if the caller asks for the output to be in threshold format, we'll
 * switch to threshold format for the last couple rounds.
 *
 * In addition, it only outputs the first 4 (64 bit) words of the final
 * state - the caller never needs any further outputs.
 *
 * Here is what we did to create this version:
 * - We extracted the permutation function (the caller does the rest of
 *   the SHAKE256 operations; absorbing the message/padding/squeezing)
 * - We reduced the number of rounds per iteration from 2 to 1.  In the
 *   original code, one iteration computed a single round of input A (result
 *   in E), and a single round of input E (result in A).
 *   We replaced this with an iteration computing a single round of input A
 *   (result in E), and then copied the state back into A.
 * - We put the linear parts of the permutation logic into macros; we left
 *   the nonlinear (chi) operations inline
 * - We put in a threshold version of the round operation; triplicating the
 *   state variables; for the linear parts, we invoked the macros for each
 *   of the 3 states; for the nonlinear parts, we wrote the appropriate and
 *   logic manually
 * - We added the state logic to process the Keccak logic, and added cases
 *   to blind/unblind the threshold, and output the end state
 */
#define BLINDED_ROUNDS 3  /* Do 3 threshold rounds at the beginning (and */
                          /* at the end if output_threshold == 1) */

#include <stddef.h>
#include <stdint.h>

#include "fips202-threshold.h"

#define NROUNDS 24
#define ROL(a, offset) (((a) << (offset)) ^ ((a) >> (64 - (offset))))

/* Keccak round constants */
static const uint64_t KeccakF_RoundConstants[NROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

/*************************************************
 * Name:        do_threshold_keccak_permutation
 *
 * Description: The threshold version of the Keccak F1600 Permutation
 *              On input, instate contains a pointer to 3 (25 word each)
 *              shares of the logical state.  The logical state are the 3
 *              sets of 25 words xor'ed together.
 *
 * Arguments:   - uint64_t *instate: pointer to input Keccak state, in
 *                    threshold format.
 *                uint64_t *outstate: pointer to output Keccak state.
 *                    If output_threshold == 0, the actual Keccak state will
 *                        be written here as 25 words
 *                    If output_threshold == 1, a threshold version of the
 *                        Keccak state will be written, as 3*25 == 75 words
 *                int output_threshold - 0 -> output unthresholded state
 *                                       1 -> output thresholded state
 **************************************************/
void do_threshold_keccak_permutation( const uint64_t *instate,
	                                    uint64_t *outstate,
				            int output_threshold )
{
    int round;
    enum keccak_state {
	Keccak_3,   /* Do 2 rounds of Keccak with the state thresholded */
	Keccak_1,   /* Do 2 rounds of Keccak only on state0 */
	Do_Xor,     /* Xor state1 and state2 into state0 (which serves as */
	            /* both the blind and unblind operations) */
	Output_3,   /* Return the thresholded state back */
	Output_1    /* Return the non thresholded state back */
    };
#if BLINDED_ROUNDS == 3
        /* CODE TO DO 3 ROUNDS OF THRESHOLD KECCAK */
    static enum keccak_state standard_output[] = {
	Keccak_3,   /* Do 3 rounds of thresholded Keccak */
	Keccak_3,
	Keccak_3,
	Do_Xor,     /* Convert to standard format */
	Keccak_1,   /* Do 21 rounds of standard Keccak */
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Output_1    /* And output that */
    };
    static enum keccak_state threshold_output[] = {
	Keccak_3,   /* Do 3 rounds of thresholded Keccak */
	Keccak_3,
	Keccak_3,
	Do_Xor,     /* Convert to standard format */
	Keccak_1,   /* Do 18 rounds of standard Keccak */
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Do_Xor,     /* Convert back into threshold format */
	Keccak_3,   /* Do three more rounds of threshold */
	Keccak_3,
	Keccak_3,
	Output_3    /* And output that */
    };
#elif BLINDED_ROUNDS == 2
        /* CODE TO DO 2 ROUNDS OF THRESHOLD KECCAK */
    static enum keccak_state standard_output[] = {
	Keccak_3,   /* Do 2 rounds of thresholded Keccak */
	Keccak_3,
	Do_Xor,     /* Convert to standard format */
	Keccak_1,   /* Do 22 rounds of standard Keccak */
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Output_1    /* And output that */
    };
    static enum keccak_state threshold_output[] = {
	Keccak_3,   /* Do 2 rounds of thresholded Keccak */
	Keccak_3,
	Do_Xor,     /* Convert to standard format */
	Keccak_1,   /* Do 20 rounds of standard Keccak */
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Keccak_1,
	Do_Xor,     /* Convert back into threshold format */
	Keccak_3,   /* Do two more rounds of threshold */
	Keccak_3,
	Output_3    /* And output that */
    };
#else
#error Unsupported number of BLINDED_ROUNDS
#endif
    enum keccak_state *state;
    if (output_threshold) {
	state = threshold_output;
    } else {
	state = standard_output;
    }

#define DECLARE(x) \
    uint64_t Aba##x, Abe##x, Abi##x, Abo##x, Abu##x; \
    uint64_t Aga##x, Age##x, Agi##x, Ago##x, Agu##x; \
    uint64_t Aka##x, Ake##x, Aki##x, Ako##x, Aku##x; \
    uint64_t Ama##x, Ame##x, Ami##x, Amo##x, Amu##x; \
    uint64_t Asa##x, Ase##x, Asi##x, Aso##x, Asu##x; \
    uint64_t BCa##x, BCe##x, BCi##x, BCo##x, BCu##x; \
    uint64_t Da##x,  De##x,  Di##x,  Do##x,  Du##x; \
    uint64_t Eba##x, Ebe##x, Ebi##x, Ebo##x, Ebu##x; \
    uint64_t Ega##x, Ege##x, Egi##x, Ego##x, Egu##x; \
    uint64_t Eka##x, Eke##x, Eki##x, Eko##x, Eku##x; \
    uint64_t Ema##x, Eme##x, Emi##x, Emo##x, Emu##x; \
    uint64_t Esa##x, Ese##x, Esi##x, Eso##x, Esu##x;

    DECLARE(0)
    DECLARE(1)
    DECLARE(2)

#define LOADSTATE(x) \
    Aba##x = instate[0+25*x]; \
    Abe##x = instate[1+25*x]; \
    Abi##x = instate[2+25*x]; \
    Abo##x = instate[3+25*x]; \
    Abu##x = instate[4+25*x]; \
    Aga##x = instate[5+25*x]; \
    Age##x = instate[6+25*x]; \
    Agi##x = instate[7+25*x]; \
    Ago##x = instate[8+25*x]; \
    Agu##x = instate[9+25*x]; \
    Aka##x = instate[10+25*x]; \
    Ake##x = instate[11+25*x]; \
    Aki##x = instate[12+25*x]; \
    Ako##x = instate[13+25*x]; \
    Aku##x = instate[14+25*x]; \
    Ama##x = instate[15+25*x]; \
    Ame##x = instate[16+25*x]; \
    Ami##x = instate[17+25*x]; \
    Amo##x = instate[18+25*x]; \
    Amu##x = instate[19+25*x]; \
    Asa##x = instate[20+25*x]; \
    Ase##x = instate[21+25*x]; \
    Asi##x = instate[22+25*x]; \
    Aso##x = instate[23+25*x]; \
    Asu##x = instate[24+25*x];

    LOADSTATE(0)
    LOADSTATE(1)
    LOADSTATE(2)

    for (round = 0;;) {
	switch (*state++) {
	case Keccak_1:
	    /* This performs a single Keccak round on the unthresholded */
	    /* state in the '0' variables */
#define STEP1(x) \
        BCa##x = Aba##x ^ Aga##x ^ Aka##x ^ Ama##x ^ Asa##x; \
        BCe##x = Abe##x ^ Age##x ^ Ake##x ^ Ame##x ^ Ase##x; \
        BCi##x = Abi##x ^ Agi##x ^ Aki##x ^ Ami##x ^ Asi##x; \
        BCo##x = Abo##x ^ Ago##x ^ Ako##x ^ Amo##x ^ Aso##x; \
        BCu##x = Abu##x ^ Agu##x ^ Aku##x ^ Amu##x ^ Asu##x; \
        Da##x = BCu##x ^ ROL(BCe##x, 1); \
        De##x = BCa##x ^ ROL(BCi##x, 1); \
        Di##x = BCe##x ^ ROL(BCo##x, 1); \
        Do##x = BCi##x ^ ROL(BCu##x, 1); \
        Du##x = BCo##x ^ ROL(BCa##x, 1); \
        Aba##x ^= Da##x; \
        BCa##x = Aba##x; \
        Age##x ^= De##x; \
        BCe##x = ROL(Age##x, 44); \
        Aki##x ^= Di##x; \
        BCi##x = ROL(Aki##x, 43); \
        Amo##x ^= Do##x; \
        BCo##x = ROL(Amo##x, 21); \
        Asu##x ^= Du##x; \
        BCu##x = ROL(Asu##x, 14);

	    STEP1(0)

            Eba0 = BCa0 ^ (~BCe0 & BCi0);
            Eba0 ^= KeccakF_RoundConstants[round];
            Ebe0 = BCe0 ^ (~BCi0 & BCo0);
            Ebi0 = BCi0 ^ (~BCo0 & BCu0);
            Ebo0 = BCo0 ^ (~BCu0 & BCa0);
            Ebu0 = BCu0 ^ (~BCa0 & BCe0);

#define STEP2(x) \
        Abo##x ^= Do##x; \
        BCa##x = ROL(Abo##x, 28); \
        Agu##x ^= Du##x; \
        BCe##x = ROL(Agu##x, 20); \
        Aka##x ^= Da##x; \
        BCi##x = ROL(Aka##x, 3); \
        Ame##x ^= De##x; \
        BCo##x = ROL(Ame##x, 45); \
        Asi##x ^= Di##x; \
        BCu##x = ROL(Asi##x, 61);

	    STEP2(0)

            Ega0 = BCa0 ^ ((~BCe0) & BCi0);
            Ege0 = BCe0 ^ ((~BCi0) & BCo0);
            Egi0 = BCi0 ^ ((~BCo0) & BCu0);
            Ego0 = BCo0 ^ ((~BCu0) & BCa0);
            Egu0 = BCu0 ^ ((~BCa0) & BCe0);

#define STEP3(x) \
        Abe##x ^= De##x; \
        BCa##x = ROL(Abe##x, 1); \
        Agi##x ^= Di##x; \
        BCe##x = ROL(Agi##x, 6); \
        Ako##x ^= Do##x; \
        BCi##x = ROL(Ako##x, 25); \
        Amu##x ^= Du##x; \
        BCo##x = ROL(Amu##x, 8); \
        Asa##x ^= Da##x; \
        BCu##x = ROL(Asa##x, 18);

	    STEP3(0)

            Eka0 = BCa0 ^ (~BCe0 & BCi0);
            Eke0 = BCe0 ^ (~BCi0 & BCo0);
            Eki0 = BCi0 ^ (~BCo0 & BCu0);
            Eko0 = BCo0 ^ (~BCu0 & BCa0);
            Eku0 = BCu0 ^ (~BCa0 & BCe0);

#define STEP4(x) \
        Abu##x ^= Du##x; \
        BCa##x = ROL(Abu##x, 27); \
        Aga##x ^= Da##x; \
        BCe##x = ROL(Aga##x, 36); \
        Ake##x ^= De##x; \
        BCi##x = ROL(Ake##x, 10); \
        Ami##x ^= Di##x; \
        BCo##x = ROL(Ami##x, 15); \
        Aso##x ^= Do##x; \
        BCu##x = ROL(Aso##x, 56);

	    STEP4(0)

        Ema0 = BCa0 ^ ((~BCe0) & BCi0);
        Eme0 = BCe0 ^ ((~BCi0) & BCo0);
        Emi0 = BCi0 ^ ((~BCo0) & BCu0);
        Emo0 = BCo0 ^ ((~BCu0) & BCa0);
        Emu0 = BCu0 ^ ((~BCa0) & BCe0);

#define STEP5(x) \
        Abi##x ^= Di##x;  \
        BCa##x = ROL(Abi##x, 62);  \
        Ago##x ^= Do##x;  \
        BCe##x = ROL(Ago##x, 55);  \
        Aku##x ^= Du##x;  \
        BCi##x = ROL(Aku##x, 39);  \
        Ama##x ^= Da##x;  \
        BCo##x = ROL(Ama##x, 41);  \
        Ase##x ^= De##x;  \
        BCu##x = ROL(Ase##x, 2);

	    STEP5(0)

        Esa0 = BCa0 ^ ((~BCe0) & BCi0);
        Ese0 = BCe0 ^ ((~BCi0) & BCo0);
        Esi0 = BCi0 ^ ((~BCo0) & BCu0);
        Eso0 = BCo0 ^ ((~BCu0) & BCa0);
        Esu0 = BCu0 ^ ((~BCa0) & BCe0);

#define COPYBACK(x) \
    Aba##x = Eba##x; \
    Abe##x = Ebe##x; \
    Abi##x = Ebi##x; \
    Abo##x = Ebo##x; \
    Abu##x = Ebu##x; \
    Aga##x = Ega##x; \
    Age##x = Ege##x; \
    Agi##x = Egi##x; \
    Ago##x = Ego##x; \
    Agu##x = Egu##x; \
    Aka##x = Eka##x; \
    Ake##x = Eke##x; \
    Aki##x = Eki##x; \
    Ako##x = Eko##x; \
    Aku##x = Eku##x; \
    Ama##x = Ema##x; \
    Ame##x = Eme##x; \
    Ami##x = Emi##x; \
    Amo##x = Emo##x; \
    Amu##x = Emu##x; \
    Asa##x = Esa##x; \
    Ase##x = Ese##x; \
    Asi##x = Esi##x; \
    Aso##x = Eso##x; \
    Asu##x = Esu##x;

	    COPYBACK(0);

	    round += 1;
	    break;
	case Keccak_3:
	    /* This performs a single Keccak round on the thresholded */
	    /* state contained within the '0', '1', '2' variables */
	    STEP1(0);
	    STEP1(1);
	    STEP1(2);

            // Eba = BCa ^ (~BCe & BCi);
            Eba0 = BCa0 ^ (~BCe0 & BCi0) ^ (~BCe1 & BCi1) ^ (~BCe2 & BCi2);
            Eba0 ^= KeccakF_RoundConstants[round];
            Eba1 = BCa1 ^ (~BCe0 & BCi1) ^ (~BCe1 & BCi2) ^ (~BCe2 & BCi0);
            Eba2 = BCa2 ^ (~BCe0 & BCi2) ^ (~BCe1 & BCi0) ^ (~BCe2 & BCi1);

            // Ebe = BCe ^ (~BCi & BCo);
            Ebe0 = BCe0 ^ (~BCi0 & BCo0) ^ (~BCi1 & BCo1) ^ (~BCi2 & BCo2);
            Ebe1 = BCe1 ^ (~BCi0 & BCo1) ^ (~BCi1 & BCo2) ^ (~BCi2 & BCo0);
            Ebe2 = BCe2 ^ (~BCi0 & BCo2) ^ (~BCi1 & BCo0) ^ (~BCi2 & BCo1);

            // Ebi = BCi ^ (~BCo & BCu);
            Ebi0 = BCi0 ^ (~BCo0 & BCu0) ^ (~BCo1 & BCu1) ^ (~BCo2 & BCu2);
            Ebi1 = BCi1 ^ (~BCo0 & BCu1) ^ (~BCo1 & BCu2) ^ (~BCo2 & BCu0);
            Ebi2 = BCi2 ^ (~BCo0 & BCu2) ^ (~BCo1 & BCu0) ^ (~BCo2 & BCu1);

	    // Ebo = BCo ^ (~BCu & BCa);
            Ebo0 = BCo0 ^ (~BCu0 & BCa0) ^ (~BCu1 & BCa1) ^ (~BCu2 & BCa2);
            Ebo1 = BCo1 ^ (~BCu0 & BCa1) ^ (~BCu1 & BCa2) ^ (~BCu2 & BCa0);
            Ebo2 = BCo2 ^ (~BCu0 & BCa2) ^ (~BCu1 & BCa0) ^ (~BCu2 & BCa1);

	    // Ebu = BCu ^ (~BCa & BCe);
            Ebu0 = BCu0 ^ (~BCa0 & BCe0) ^ (~BCa1 & BCe1) ^ (~BCa2 & BCe2);
            Ebu1 = BCu1 ^ (~BCa0 & BCe1) ^ (~BCa1 & BCe2) ^ (~BCa2 & BCe0);
            Ebu2 = BCu2 ^ (~BCa0 & BCe2) ^ (~BCa1 & BCe0) ^ (~BCa2 & BCe1);

	    STEP2(0)
	    STEP2(1)
	    STEP2(2)

            // Ega = BCa ^ ((~BCe) & BCi);
            Ega0 = BCa0 ^ (~BCe0 & BCi0) ^ (~BCe1 & BCi1) ^ (~BCe2 & BCi2);
            Ega1 = BCa1 ^ (~BCe0 & BCi1) ^ (~BCe1 & BCi2) ^ (~BCe2 & BCi0);
            Ega2 = BCa2 ^ (~BCe0 & BCi2) ^ (~BCe1 & BCi0) ^ (~BCe2 & BCi1);
            // Ege = BCe ^ ((~BCi) & BCo);
            Ege0 = BCe0 ^ (~BCi0 & BCo0) ^ (~BCi1 & BCo1) ^ (~BCi2 & BCo2);
            Ege1 = BCe1 ^ (~BCi0 & BCo1) ^ (~BCi1 & BCo2) ^ (~BCi2 & BCo0);
            Ege2 = BCe2 ^ (~BCi0 & BCo2) ^ (~BCi1 & BCo0) ^ (~BCi2 & BCo1);
            // Egi = BCi ^ ((~BCo) & BCu);
            Egi0 = BCi0 ^ (~BCo0 & BCu0) ^ (~BCo1 & BCu1) ^ (~BCo2 & BCu2);
            Egi1 = BCi1 ^ (~BCo0 & BCu1) ^ (~BCo1 & BCu2) ^ (~BCo2 & BCu0);
            Egi2 = BCi2 ^ (~BCo0 & BCu2) ^ (~BCo1 & BCu0) ^ (~BCo2 & BCu1);
            // Ego = BCo ^ ((~BCu) & BCa);
            Ego0 = BCo0 ^ (~BCu0 & BCa0) ^ (~BCu1 & BCa1) ^ (~BCu2 & BCa2);
            Ego1 = BCo1 ^ (~BCu0 & BCa1) ^ (~BCu1 & BCa2) ^ (~BCu2 & BCa0);
            Ego2 = BCo2 ^ (~BCu0 & BCa2) ^ (~BCu1 & BCa0) ^ (~BCu2 & BCa1);
            // Egu = BCu ^ ((~BCa) & BCe);
            Egu0 = BCu0 ^ (~BCa0 & BCe0) ^ (~BCa1 & BCe1) ^ (~BCa2 & BCe2);
            Egu1 = BCu1 ^ (~BCa0 & BCe1) ^ (~BCa1 & BCe2) ^ (~BCa2 & BCe0);
            Egu2 = BCu2 ^ (~BCa0 & BCe2) ^ (~BCa1 & BCe0) ^ (~BCa2 & BCe1);

	    STEP3(0)
	    STEP3(1)
	    STEP3(2)

            // Eka = BCa ^ ((~BCe) & BCi);
            Eka0 = BCa0 ^ (~BCe0 & BCi0) ^ (~BCe1 & BCi1) ^ (~BCe2 & BCi2);
            Eka1 = BCa1 ^ (~BCe0 & BCi1) ^ (~BCe1 & BCi2) ^ (~BCe2 & BCi0);
            Eka2 = BCa2 ^ (~BCe0 & BCi2) ^ (~BCe1 & BCi0) ^ (~BCe2 & BCi1);
            // Eke = BCe ^ ((~BCi) & BCo);
            Eke0 = BCe0 ^ (~BCi0 & BCo0) ^ (~BCi1 & BCo1) ^ (~BCi2 & BCo2);
            Eke1 = BCe1 ^ (~BCi0 & BCo1) ^ (~BCi1 & BCo2) ^ (~BCi2 & BCo0);
            Eke2 = BCe2 ^ (~BCi0 & BCo2) ^ (~BCi1 & BCo0) ^ (~BCi2 & BCo1);
            // Eki = BCi ^ ((~BCo) & BCu);
            Eki0 = BCi0 ^ (~BCo0 & BCu0) ^ (~BCo1 & BCu1) ^ (~BCo2 & BCu2);
            Eki1 = BCi1 ^ (~BCo0 & BCu1) ^ (~BCo1 & BCu2) ^ (~BCo2 & BCu0);
            Eki2 = BCi2 ^ (~BCo0 & BCu2) ^ (~BCo1 & BCu0) ^ (~BCo2 & BCu1);
            // Eko = BCo ^ ((~BCu) & BCa);
            Eko0 = BCo0 ^ (~BCu0 & BCa0) ^ (~BCu1 & BCa1) ^ (~BCu2 & BCa2);
            Eko1 = BCo1 ^ (~BCu0 & BCa1) ^ (~BCu1 & BCa2) ^ (~BCu2 & BCa0);
            Eko2 = BCo2 ^ (~BCu0 & BCa2) ^ (~BCu1 & BCa0) ^ (~BCu2 & BCa1);
            // Eku = BCu ^ ((~BCa) & BCe);
            Eku0 = BCu0 ^ (~BCa0 & BCe0) ^ (~BCa1 & BCe1) ^ (~BCa2 & BCe2);
            Eku1 = BCu1 ^ (~BCa0 & BCe1) ^ (~BCa1 & BCe2) ^ (~BCa2 & BCe0);
            Eku2 = BCu2 ^ (~BCa0 & BCe2) ^ (~BCa1 & BCe0) ^ (~BCa2 & BCe1);

	    STEP4(0)
	    STEP4(1)
	    STEP4(2)

            // Ema = BCa ^ ((~BCe) & BCi);
            Ema0 = BCa0 ^ (~BCe0 & BCi0) ^ (~BCe1 & BCi1) ^ (~BCe2 & BCi2);
            Ema1 = BCa1 ^ (~BCe0 & BCi1) ^ (~BCe1 & BCi2) ^ (~BCe2 & BCi0);
            Ema2 = BCa2 ^ (~BCe0 & BCi2) ^ (~BCe1 & BCi0) ^ (~BCe2 & BCi1);
            // Eme = BCe ^ ((~BCi) & BCo);
            Eme0 = BCe0 ^ (~BCi0 & BCo0) ^ (~BCi1 & BCo1) ^ (~BCi2 & BCo2);
            Eme1 = BCe1 ^ (~BCi0 & BCo1) ^ (~BCi1 & BCo2) ^ (~BCi2 & BCo0);
            Eme2 = BCe2 ^ (~BCi0 & BCo2) ^ (~BCi1 & BCo0) ^ (~BCi2 & BCo1);
            // Emi = BCi ^ ((~BCo) & BCu);
            Emi0 = BCi0 ^ (~BCo0 & BCu0) ^ (~BCo1 & BCu1) ^ (~BCo2 & BCu2);
            Emi1 = BCi1 ^ (~BCo0 & BCu1) ^ (~BCo1 & BCu2) ^ (~BCo2 & BCu0);
            Emi2 = BCi2 ^ (~BCo0 & BCu2) ^ (~BCo1 & BCu0) ^ (~BCo2 & BCu1);
            // Emo = BCo ^ ((~BCu) & BCa);
            Emo0 = BCo0 ^ (~BCu0 & BCa0) ^ (~BCu1 & BCa1) ^ (~BCu2 & BCa2);
            Emo1 = BCo1 ^ (~BCu0 & BCa1) ^ (~BCu1 & BCa2) ^ (~BCu2 & BCa0);
            Emo2 = BCo2 ^ (~BCu0 & BCa2) ^ (~BCu1 & BCa0) ^ (~BCu2 & BCa1);
            // Emu = BCu ^ ((~BCa) & BCe);
            Emu0 = BCu0 ^ (~BCa0 & BCe0) ^ (~BCa1 & BCe1) ^ (~BCa2 & BCe2);
            Emu1 = BCu1 ^ (~BCa0 & BCe1) ^ (~BCa1 & BCe2) ^ (~BCa2 & BCe0);
            Emu2 = BCu2 ^ (~BCa0 & BCe2) ^ (~BCa1 & BCe0) ^ (~BCa2 & BCe1);

	    STEP5(0)
	    STEP5(1)
	    STEP5(2)

            // Esa = BCa ^ ((~BCe) & BCi);
            Esa0 = BCa0 ^ (~BCe0 & BCi0) ^ (~BCe1 & BCi1) ^ (~BCe2 & BCi2);
            Esa1 = BCa1 ^ (~BCe0 & BCi1) ^ (~BCe1 & BCi2) ^ (~BCe2 & BCi0);
            Esa2 = BCa2 ^ (~BCe0 & BCi2) ^ (~BCe1 & BCi0) ^ (~BCe2 & BCi1);
            // Ese = BCe ^ ((~BCi) & BCo);
            Ese0 = BCe0 ^ (~BCi0 & BCo0) ^ (~BCi1 & BCo1) ^ (~BCi2 & BCo2);
            Ese1 = BCe1 ^ (~BCi0 & BCo1) ^ (~BCi1 & BCo2) ^ (~BCi2 & BCo0);
            Ese2 = BCe2 ^ (~BCi0 & BCo2) ^ (~BCi1 & BCo0) ^ (~BCi2 & BCo1);
            // Esi = BCi ^ ((~BCo) & BCu);
            Esi0 = BCi0 ^ (~BCo0 & BCu0) ^ (~BCo1 & BCu1) ^ (~BCo2 & BCu2);
            Esi1 = BCi1 ^ (~BCo0 & BCu1) ^ (~BCo1 & BCu2) ^ (~BCo2 & BCu0);
            Esi2 = BCi2 ^ (~BCo0 & BCu2) ^ (~BCo1 & BCu0) ^ (~BCo2 & BCu1);
            // Eso = BCo ^ ((~BCu) & BCa);
            Eso0 = BCo0 ^ (~BCu0 & BCa0) ^ (~BCu1 & BCa1) ^ (~BCu2 & BCa2);
            Eso1 = BCo1 ^ (~BCu0 & BCa1) ^ (~BCu1 & BCa2) ^ (~BCu2 & BCa0);
            Eso2 = BCo2 ^ (~BCu0 & BCa2) ^ (~BCu1 & BCa0) ^ (~BCu2 & BCa1);
            // Esu = BCu ^ ((~BCa) & BCe);
            Esu0 = BCu0 ^ (~BCa0 & BCe0) ^ (~BCa1 & BCe1) ^ (~BCa2 & BCe2);
            Esu1 = BCu1 ^ (~BCa0 & BCe1) ^ (~BCa1 & BCe2) ^ (~BCa2 & BCe0);
            Esu2 = BCu2 ^ (~BCa0 & BCe2) ^ (~BCa1 & BCe0) ^ (~BCa2 & BCe1);

	    COPYBACK(0);
	    COPYBACK(1);
	    COPYBACK(2);

	    round += 1;
	    break;
	case Do_Xor:
	       /* This converts between the standard and the threshold */
	       /* versions.  Yes, the same logic does both */
	    Aba0 ^= Aba1 ^ Aba2;
	    Abe0 ^= Abe1 ^ Abe2;
	    Abi0 ^= Abi1 ^ Abi2;
	    Abo0 ^= Abo1 ^ Abo2;
	    Abu0 ^= Abu1 ^ Abu2;
	    Aga0 ^= Aga1 ^ Aga2;
	    Age0 ^= Age1 ^ Age2;
	    Agi0 ^= Agi1 ^ Agi2;
	    Ago0 ^= Ago1 ^ Ago2;
	    Agu0 ^= Agu1 ^ Agu2;
	    Aka0 ^= Aka1 ^ Aka2;
	    Ake0 ^= Ake1 ^ Ake2;
	    Aki0 ^= Aki1 ^ Aki2;
	    Ako0 ^= Ako1 ^ Ako2;
	    Aku0 ^= Aku1 ^ Aku2;
	    Ama0 ^= Ama1 ^ Ama2;
	    Ame0 ^= Ame1 ^ Ame2;
	    Ami0 ^= Ami1 ^ Ami2;
	    Amo0 ^= Amo1 ^ Amo2;
	    Amu0 ^= Amu1 ^ Amu2;
	    Asa0 ^= Asa1 ^ Asa2;
	    Ase0 ^= Ase1 ^ Ase2;
	    Asi0 ^= Asi1 ^ Asi2;
	    Aso0 ^= Aso1 ^ Aso2;
	    Asu0 ^= Asu1 ^ Asu2;
	    break;
	case Output_1:
	        /* This outputs the standard (non-threshold) state in the */
	        /* '0' variables */
#define DO_OUTPUT(x) \
    outstate[0+25*x] = Aba##x; \
    outstate[1+25*x] = Abe##x; \
    outstate[2+25*x] = Abi##x; \
    outstate[3+25*x] = Abo##x; \
        /* If we need more than 256 bits of state, add the outputs here */

            DO_OUTPUT(0);
	    return;
	case Output_3:
	        /* This outputs the threshold state */
            DO_OUTPUT(0);
            DO_OUTPUT(1);
            DO_OUTPUT(2);
	    return;
	}
    }
}
