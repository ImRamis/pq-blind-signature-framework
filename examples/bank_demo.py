#!/usr/bin/env python3
"""
Bank Demo: Anonymous Digital Cash (E-Cash)

This script runs a demonstration of the blind signature schemes in a simulated
e-cash scenario. It shows the issuance of a coin and then tests the cryptographic
security by attempting a forgery.
"""
import sys
import os
import secrets
from typing import Dict, Any, Optional
from dataclasses import dataclass

# Make the 'src' directory available for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.blind_signatures.config import display_config
from src.blind_signatures import (
    FischlinBlindSignature, KlooReichleWagnerSignature, HanzlikNIBS, HanzlikTNIBS,
    UnblindedSignature
)
from src.blind_signatures.core.practical_protocol import FinalSignature as KRWFinalSignature
from src.blind_signatures.utils.serialization import to_dict
from py_ecc.optimized_bls12_381 import FQ, FQ2, multiply

# --- Demo Configuration ---
COIN_FORMAT = "E_CASH_COIN_V1_SERIAL::{serial_number}"

@dataclass
class IssuedCoin:
    """Represents a digital coin issued by the bank."""
    serial_number: str
    signature: Dict[str, Any]
    value: int = 100
    # Hanzlik schemes produce a random message point, store it here
    hanzlik_m_point: Optional[tuple] = None

# --- Helper function to fix data types after JSON conversion ---
def lists_to_tuples(data: Any) -> Any:
    """Recursively converts lists to tuples in a nested structure."""
    if isinstance(data, list):
        return tuple(lists_to_tuples(item) for item in data)
    if isinstance(data, dict):
        return {key: lists_to_tuples(value) for key, value in data.items()}
    return data

# --- Main Demo Logic ---
def run_ecash_demo(scheme_name: str):
    """Executes a full e-cash demonstration for a given blind signature scheme."""
    print("\n" + "="*70)
    print(f"--- E-CASH DEMONSTRATION: The '{scheme_name}' Protocol ---")
    print("="*70)

    # === 1. SETUP PHASE ===
    # The Bank sets up the cryptographic system and generates its keys.
    print("\n[SETUP] The Bank is setting up the cryptographic system...")
    if scheme_name == "Fischlin":
        protocol = FischlinBlindSignature()
        protocol.setup()
        bank_keys = protocol.signer_keygen()
    elif scheme_name == "Practical":
        protocol = KlooReichleWagnerSignature()
        bank_keys = protocol.keygen()
    else: # Hanzlik
        protocol = HanzlikNIBS()
        sk, pk = protocol.keygen()
        @dataclass
        class HanzlikKeys: secret_key: Any; public_key: Any
        bank_keys = HanzlikKeys(secret_key=sk, public_key=pk)
    print(f"✓ Bank for '{scheme_name}' is online and keys have been generated.")

    # === 2. WITHDRAWAL (ISSUANCE) PHASE ===
    # A User requests a blinded digital coin from the Bank.
    print(f"\n[ISSUANCE] User requests to withdraw one digital coin...")
    
    serial_number = secrets.token_hex(16)
    coin_message = COIN_FORMAT.format(serial_number=serial_number).encode()
    print(f"  - User creates secret serial number: {serial_number[:12]}...")

    signature_data = None
    hanzlik_m_point = None
    if scheme_name == "Hanzlik":
        rec_sk, rec_pk = protocol.rkeygen()
        psig = protocol.issue(bank_keys.secret_key, rec_pk, coin_message)
        obtained = protocol.obtain(rec_sk, bank_keys.public_key, psig, coin_message)
        if obtained:
            hanzlik_m_point, sig_tuple = obtained
            signature_data = to_dict(sig_tuple)
    elif scheme_name == "Fischlin":
        request, user_state = protocol.create_request(coin_message, bank_keys.encryption_key)
        response = protocol.create_response(request, bank_keys)
        final_sig = protocol.unblind_signature(response, user_state, bank_keys.verification_key)
        if final_sig: signature_data = to_dict(final_sig.signature)
    elif scheme_name == "Practical":
        user_msg1, user_state = protocol.user_step1(coin_message, bank_keys)
        signer_msg1, signer_state = protocol.signer_step1(user_msg1, bank_keys)
        user_msg2 = protocol.user_step2(signer_msg1, user_state, bank_keys)
        signer_msg2 = protocol.signer_step2(user_msg2, signer_state, bank_keys)
        final_sig = protocol.user_finalize(signer_msg2, user_state)
        if final_sig: signature_data = to_dict(final_sig)

    if not signature_data:
        print("  - [❌ FAIL] Issuance protocol failed.")
        return

    issued_coin = IssuedCoin(serial_number, signature_data, hanzlik_m_point=hanzlik_m_point)
    print("✓ Issuance successful. User now has a signed, anonymous digital coin.")

    # === 3. SPEND (VERIFICATION) & FORGERY TEST ===
    def verify_coin(c: IssuedCoin, is_forgery_test: bool = False, forged_m_point: Optional[tuple] = None):
        print(f"\n>>> Verifying coin with serial '{c.serial_number[:12]}...' <<<")
        
        message_to_verify_bytes = COIN_FORMAT.format(serial_number=c.serial_number).encode()
        is_valid = False
        
        try:
            if scheme_name == "Hanzlik":
                sig_parts = c.signature
                reconstructed_sig = (
                    tuple(FQ(coord) for coord in sig_parts[0]),
                    tuple(FQ(coord) for coord in sig_parts[1]),
                    tuple(FQ2(coords) for coords in sig_parts[2]),
                )
                m_to_verify = forged_m_point if is_forgery_test else c.hanzlik_m_point
                is_valid = protocol.verify(bank_keys.public_key, m_to_verify, reconstructed_sig)
            elif scheme_name == "Fischlin":
                sig_obj = UnblindedSignature(signature=c.signature, message=message_to_verify_bytes)
                is_valid = protocol.verify_signature(sig_obj, bank_keys.verification_key)
            elif scheme_name == "Practical":
                sig_data_as_tuples = lists_to_tuples(c.signature)
                sig_obj = KRWFinalSignature(**sig_data_as_tuples)
                is_valid = protocol.verify(message_to_verify_bytes, sig_obj, bank_keys)
        except Exception as e:
            print(f"  - Verification threw an exception: {e}")
            is_valid = False

        if is_forgery_test:
            print(f"  - RESULT: {'[✅ PASS] Forgery correctly detected!' if not is_valid else '[❌ FAIL] Forgery was accepted!'}")
        else:
            print(f"  - RESULT: {'[✅ VALID]' if is_valid else '[❌ INVALID]'}")

    # 1. Verify the original, valid coin
    verify_coin(issued_coin)

    # 2. Attempt a forgery
    print("\n" + "-"*20 + " FORGERY ATTEMPT " + "-"*20)
    if scheme_name == "Hanzlik":
        forged_m_point = multiply(protocol.g1, secrets.randbelow(protocol.order))
        verify_coin(issued_coin, is_forgery_test=True, forged_m_point=forged_m_point)
    else:
        forged_serial_number = secrets.token_hex(16)
        forged_coin = IssuedCoin(
            serial_number=forged_serial_number,
            signature=issued_coin.signature, # Re-using the old signature
        )
        verify_coin(forged_coin, is_forgery_test=True)


def main():
    """Runs the e-cash demo for all three schemes."""
    display_config()
    run_ecash_demo("Fischlin")
    run_ecash_demo("Practical")
    run_ecash_demo("Hanzlik")
    print("\n" + "="*70)
    print("All e-cash demonstrations complete.")
    print("="*70)

if __name__ == "__main__":
    main()