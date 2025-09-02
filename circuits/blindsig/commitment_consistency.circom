pragma circom 2.0.0;

// The circomlib library is expected to be in `node_modules` at the project root.
include "../../snarkjs_engine/node_modules/circomlib/circuits/pedersen.circom";
include "../../snarkjs_engine/node_modules/circomlib/circuits/bitify.circom";

/*
 * This circuit enforces the core security property of the Fischlin blind signature scheme.
 * It proves, in zero-knowledge, that a user has created a Pedersen commitment and an
 * encryption to the *same secret message* without revealing the message itself.
 *
 * This version uses a standard Pedersen hash implementation from circomlib over the
 * BabyJubJub curve, replacing the previous pseudo-commitment.
 *
 * It ensures that the message committed to is the same one being encrypted for the signer.
 */

// The Pedersen hash in circomlib takes a fixed number of bits. The total number of bits
// must be a multiple of 248 for the internal MiMC sponge. We use 248 bits for the message
// and 248 bits for the randomness, for a total of 496 bits.
template CommitmentConsistency(msg_bits, rand_bits) {
    // --- Private Inputs (Witness) ---
    // The secret values known only to the prover (user).
    // These are passed as field elements.
    signal input message;
    signal input randomness;

    // --- Public Inputs (Statement) ---
    // The public values that the proof is about.
    signal input commitmentX; // The x-coordinate of the Pedersen commitment point
    signal input commitmentY; // The y-coordinate of the Pedersen commitment point
    signal input encrypted_message;
    signal input encryption_key;

    // --- Logic ---

    // 1. Convert private inputs from field elements to bits.
    // This is necessary because the Pedersen hash component operates on bits.
    component msg_to_bits = Num2Bits(msg_bits);
    msg_to_bits.in <== message;

    component rand_to_bits = Num2Bits(rand_bits);
    rand_to_bits.in <== randomness;

    // 2. Compute the Pedersen Commitment in-circuit.
    // The Pedersen hash component takes a single flat array of bits.
    // We concatenate the message bits and randomness bits.
    var total_bits = msg_bits + rand_bits;
    component pedersen = Pedersen(total_bits);

    for (var i = 0; i < msg_bits; i++) {
        pedersen.in[i] <== msg_to_bits.out[i];
    }
    for (var i = 0; i < rand_bits; i++) {
        pedersen.in[msg_bits + i] <== rand_to_bits.out[i];
    }

    // --- Constraints ---

    // Constraint 1: Verify the Pedersen commitment.
    // The public commitment point (commitmentX, commitmentY) must match the output
    // of the in-circuit Pedersen hash computation.
    // log the commitmentX and commitmentY and the pedersen.out


    commitmentX === pedersen.out[0];
    commitmentY === pedersen.out[1];

    // Constraint 2: Verify the simplified ElGamal encryption.
    // This constraint links the commitment to the encryption. It ensures the `message`
    // field element that was committed to (by converting to bits) is the same
    // field element that was encrypted.
    signal computedEncryption;
    computedEncryption <== message * encryption_key;
    encrypted_message === computedEncryption;
}

// Instantiate the main component.
// The total number of bits (msg_bits + rand_bits) must be a multiple of 248.
// We choose 248 for both, totaling 496 bits. This allows the message to be
// nearly a full field element.
component main = CommitmentConsistency(248, 248);