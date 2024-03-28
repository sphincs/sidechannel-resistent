This is a version of SLH-DSA that aspires to be side channel resistant.  That is, it is designed so that someone who can listen into the electrical noise during the key generation and signing operations will not be able to recover enough information to generate forgeries.

Notes:
- I stated that it aspires to be side channel resistant; not that it actually does.  Further study will be needed to ascertain if (and to what extent) it fulfills that aspiration.
- This code is based on the Sphincs+ reference code.  The reference branch contains the exact version of the code it is based on.
- It does not formally meet the SLH-DSA specification; the mapping between private keys and public keys, and the mapping from private keys, message and optrand to signatures are not as specified in FIPS-205.  On the other hand, the signatures and public keys are compatible with the standard SLH-DSA verification process.
- It implements only the SHAKE-simple parameter sets.  The robust parameter sets would not be difficult to implement; the SHA2 and Haraka parameter sets would be quite difficult.
- On my test machine, it runs 70% slower than the reference (nonAVX) implementation. 
