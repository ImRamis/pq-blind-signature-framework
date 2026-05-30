pragma circom 2.0.0;
// 1) Decompose scalars
include "../../snarkjs_engine/node_modules/circomlib/circuits/bitify.circom"; 
// 2) Fixed-base and variable-base multiplication gadgets
include "../../snarkjs_engine/node_modules/circomlib/circuits/escalarmulfix.circom"; 
include "../../snarkjs_engine/node_modules/circomlib/circuits/escalarmulany.circom"; 
// 3) BabyJubJub addition
include "../../snarkjs_engine/node_modules/circomlib/circuits/babyjub.circom"; 
template SignatureConsistency() {
    // --- Witness (private)
    signal input s; // 
    // Schnorr signature scalar 

    // --- Public inputs
    signal input R_x; 
    signal input R_y; 
    signal input vk_sig_x; 
    signal input vk_sig_y; 
    signal input e;              // H(R, vk_sig, m) 
    signal input encrypted_s; 
    // ElGamal‐style encryption of s 
    signal input pk_user; 
    // User’s ElGamal public key 

    // 1) Decompose s and e into 253‐bit little‐endian arrays
    component sBits = Num2Bits(253); 
    sBits.in <== s; 
    component eBits = Num2Bits(253); 
    eBits.in <== e; 
    // 2) Compute s·G
    //    (BASE8 is the standard BabyJub generator in twisted-Edwards form) 
    var BASE8[2] = [
      5299619240641551281634865583518297030282874472190772894086521144482721001553,
      16950150798460657717958625567821834550301663161624707787222815936182638968203
    ]; 
    component sG = EscalarMulFix(253, BASE8); 
    for (var i = 0; i < 253; i++) {
        sG.e[i] <== sBits.out[i]; 
    }

    // 3) Compute e·vk_sig
    component eVk = EscalarMulAny(253); 
    for (var i = 0; i < 253; i++) {
        eVk.e[i] <== eBits.out[i]; 
    }
    eVk.p[0] <== vk_sig_x; 
    eVk.p[1] <== vk_sig_y; 
    // 4) Add R + e·vk_sig
    component Rplus = BabyAdd(); 
    Rplus.x1 <== R_x; 
    Rplus.y1 <== R_y; 
    Rplus.x2 <== eVk.out[0]; 
    Rplus.y2 <== eVk.out[1]; 

    // 5) Enforce Schnorr equation:  s*G == R + e*vk_sig
    sG.out[0] === Rplus.xout; 
    sG.out[1] === Rplus.yout; 

    // 6) Enforce “encrypted_s = s * pk_user”
    signal computed_enc <== s * pk_user; 
    encrypted_s === computed_enc; 
}

component main = SignatureConsistency(); 