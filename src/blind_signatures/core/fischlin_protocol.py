"""
Core implementation of Fischlin's Round-Optimal Composable Blind Signatures.
Paper: "Round-Optimal Composable Blind Signatures in the Common Reference String Model"
"""

from typing import Tuple, Optional, Dict, Any
import secrets

from ..crypto import PedersenCommitment, ElGamalEncryption, SchnorrSignature
from ..nizk import NIZK, NIZKStatement, NIZKWitness
from ..common import (
    CRS, SignerKeyPair, BlindSignatureRequest, BlindSignatureResponse,
    UnblindedSignature, encode_message
)
from .. import config
# Import the curve order for the BLS12-381 curve used by snarkjs
from py_ecc.optimized_bls12_381 import curve_order as bls12_381_order

CIRCOM_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617
def int_to_bit_array(n: int, num_bits: int) -> list[bool]:
    """Converts an integer to a fixed-size array of booleans (bits)."""
    return [bool((n >> i) & 1) for i in range(num_bits)]

class FischlinBlindSignature:
    """
    Implements the round-optimal composable blind signature scheme by Fischlin.
    This class contains the raw cryptographic logic for the protocol.
    """
    def __init__(self, security_param: int = 128):
        self.security_param = security_param
        self.commitment = PedersenCommitment()
        self.encryption = ElGamalEncryption()
        self.signature = SchnorrSignature()
        self.nizk = NIZK(security_param)
        self.crs: Optional[CRS] = None

    def setup(self) -> CRS:
        """Generate Common Reference String (CRS) for the entire system."""
        commitment_params = self.commitment.setup()
        encryption_params = {'type': 'elgamal'}
        signature_params = {'type': 'schnorr'}

        is_dummy_setup = config.ZK_BACKEND == 'sonic-ucse' and config.SONIC_UCSE_USE_DUMMY_SRS
        
        # Setup for the first circuit is always needed.
        nizk_params = self.nizk.setup('commitment_consistency', use_dummy=is_dummy_setup)

        # BUG FIX: Only set up the second circuit if the backend is snarkjs,
        # as it's the only one that uses it. This avoids state issues with sonic-ucse.
        if config.ZK_BACKEND == 'snarkjs':
            self.nizk.setup('signature_consistency', use_dummy=is_dummy_setup)
        
        self.crs = CRS(
            commitment_params=commitment_params,
            encryption_params=encryption_params,
            signature_params=signature_params,
            nizk_params=nizk_params
        )
        return self.crs

    def signer_keygen(self) -> SignerKeyPair:
        """Generate a key pair for the signer."""
        signing_key, verification_key = self.signature.keygen()
        decryption_key, encryption_key = self.encryption.keygen()

        return SignerKeyPair(
            signing_key=signing_key, verification_key=verification_key,
            encryption_key=encryption_key, decryption_key=decryption_key
        )

    def create_request(self, message: bytes,
                       signer_encryption_key: Tuple[int, int]) -> Tuple[BlindSignatureRequest, Dict[str, Any]]:
        """User creates the first message in the protocol: a blind signature request."""
        msg_int = encode_message(message, self.commitment.order)
        real_commitment, r_com = self.commitment.commit(msg_int)
        user_sk, user_pk = self.encryption.keygen()
        encrypted_msg = self.encryption.encrypt(signer_encryption_key, msg_int)

        proof = {}
        if config.ZK_BACKEND == 'snarkjs':
            BITLEN, MASK = 248, (1 << 248) - 1
            t_msg, t_rand = msg_int & MASK, r_com & MASK
            ped_pt = self.nizk.prover.calculate_pedersen(t_msg, t_rand)
            ek_circ = signer_encryption_key[0] % CIRCOM_PRIME
            simp_enc = (t_msg * ek_circ) % CIRCOM_PRIME

            statement = NIZKStatement(
                public_inputs={'commitmentX': ped_pt[0], 'commitmentY': ped_pt[1], 'encrypted_message': str(simp_enc), 'encryption_key': str(ek_circ)},
                relation='commitment_encryption_consistency'
            )
            witness = NIZKWitness(private_inputs={'message': str(t_msg), 'randomness': str(t_rand)})
            proof = self.nizk.prove(statement, witness)
        elif config.ZK_BACKEND == 'sonic-ucse':
            statement = NIZKStatement(
                public_inputs={}, relation='commitment_consistency'
            )
            witness_bits = int_to_bit_array(msg_int, config.SONIC_UCSE_DUMMY_PREIMAGE_BITS)
            witness = NIZKWitness(private_inputs={'message_bits': witness_bits})
            proof = self.nizk.prove(statement, witness)
        
        request = BlindSignatureRequest(encrypted_message=encrypted_msg, commitment=real_commitment, proof=proof, user_public_key=user_pk)
        user_state = {'message': message, 'user_sk': user_sk, 'randomness': r_com}
        return request, user_state

    def create_response(self, request: BlindSignatureRequest,
                        signer_keys: SignerKeyPair) -> Optional[BlindSignatureResponse]:
        """Signer verifies the request and creates the second message: a blind signature response."""
        if not self.nizk.verify(request.proof):
            return None

        try:
            msg_int = self.encryption.decrypt(signer_keys.decryption_key, request.encrypted_message)
        except Exception:
            return None

        message_to_sign_bytes = str(msg_int).encode()
        signature = self.signature.sign(signer_keys.signing_key, message_to_sign_bytes)

        encrypted_s_real = self.encryption.encrypt(request.user_public_key, signature['s'], label=b"SIG")
        encrypted_signature = {'R': signature['R'], **encrypted_s_real}

        proof = {}
        if config.ZK_BACKEND == 'snarkjs':
            pk_user_point = request.user_public_key
            pk_user_scalar = pk_user_point[0] % CIRCOM_PRIME
            encrypted_s_scalar = (signature['s'] * pk_user_scalar) % CIRCOM_PRIME
            
            statement = NIZKStatement(
                public_inputs={
                    'R_x': str(signature['R'][0]), 'R_y': str(signature['R'][1]),
                    'vk_sig_x': str(signer_keys.verification_key[0]), 'vk_sig_y': str(signer_keys.verification_key[1]),
                    'e': str(signature['e']), 'encrypted_s': str(encrypted_s_scalar), 'pk_user': str(pk_user_scalar)
                },
                relation='signature_consistency'
            )
            witness = NIZKWitness(private_inputs={'s': str(signature['s'])})
            proof = self.nizk.prove(statement, witness)

        response = BlindSignatureResponse(encrypted_signature=encrypted_signature, proof=proof)
        return response

    def unblind_signature(self, response: BlindSignatureResponse, user_state: Dict[str, Any],
                          signer_vk: Tuple[int, int]) -> Optional[UnblindedSignature]:
        """User unblinds the signature by decrypting the response from the signer."""
        if config.ZK_BACKEND == 'snarkjs':
            if not self.nizk.verify(response.proof):
                return None

        try:
            s_component = self.encryption.decrypt(user_state['user_sk'], response.encrypted_signature)
            final_signature = {'R': response.encrypted_signature['R'], 's': s_component}
            return UnblindedSignature(signature=final_signature, message=user_state['message'])
        except Exception:
            return None

    def verify_signature(self, signature: UnblindedSignature, signer_vk: Tuple[int, int]) -> bool:
        """Any third party can verify the final, unblinded signature."""
        # To verify, we must reconstruct the exact integer the signer saw and signed.
        # This integer was encoded using the *commitment* scheme's order.
        msg_int = encode_message(signature.message, self.commitment.order)
        message_to_verify_bytes = str(msg_int).encode()
        
        return self.signature.verify(signer_vk, message_to_verify_bytes, signature.signature)