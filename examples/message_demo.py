#!/usr/bin/env python3
"""
Message Demo: Demonstrates issuing and verifying a signed message.

This script runs a demonstration of the blind signature schemes in a simulated
scenario where a User gets a digital message signed by an Issuer. It also
showcases a forgery attempt to test the scheme's security.
"""
import sys
import os
import secrets
from typing import Dict, Optional, Any
from dataclasses import dataclass

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.blind_signatures.config import display_config
from src.blind_signatures import (
    FischlinBlindSignature, KlooReichleWagnerSignature, HanzlikNIBS, HanzlikTNIBS,
    UnblindedSignature
)
from src.blind_signatures.core.practical_protocol import FinalSignature as KRWFinalSignature
from src.blind_signatures.utils.serialization import to_dict
# FIX: Import the 'multiply' function directly to create the forged point
from py_ecc.optimized_bls12_381 import FQ, FQ2, multiply

# --- Demo Configuration ---
MESSAGE_FORMAT = "MESSAGE:{serial_number}:{message}"

@dataclass
class IssuedMessage:
    serial_number: str
    message: str
    signature: Dict[str, Any]
    tag: Optional[bytes] = None
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

# --- Main Demo ---
def run_demo(scheme_name: str, message_content: str, tag: Optional[bytes] = None):
    print("\n" + "="*60)
    print(f"--- DEMONSTRATION: {scheme_name} ---")
    if tag:
        print(f"--- TAG: {tag.decode()} ---")
    print("="*60)

    # --- Setup ---
    is_tagged = "Tagged" in scheme_name
    if scheme_name == "Fischlin":
        protocol = FischlinBlindSignature()
        protocol.setup()
        issuer_keys = protocol.signer_keygen()
    elif scheme_name == "Practical":
        protocol = KlooReichleWagnerSignature()
        issuer_keys = protocol.keygen()
    else: # Hanzlik or Hanzlik (Tagged)
        protocol = HanzlikTNIBS() if is_tagged else HanzlikNIBS()
        sk, pk = protocol.keygen()
        @dataclass
        class HanzlikKeys: secret_key: Any; public_key: Any
        issuer_keys = HanzlikKeys(secret_key=sk, public_key=pk)

    print(f"✓ Issuer for '{scheme_name}' initialized.")

    # --- Issuance ---
    print(f"\nUser requests a digital message for '{message_content}'...")
    serial_number = secrets.token_hex(16)
    message_str = MESSAGE_FORMAT.format(serial_number=serial_number, message=message_content)

    signature_data = None
    hanzlik_m_point = None
    if "Hanzlik" in scheme_name:
        rec_sk, rec_pk = protocol.rkeygen()
        if is_tagged:
            psig = protocol.issue(issuer_keys.secret_key, rec_pk, message_str.encode(), tag)
            obtained = protocol.obtain(rec_sk, issuer_keys.public_key, psig, message_str.encode(), tag)
        else:
            psig = protocol.issue(issuer_keys.secret_key, rec_pk, message_str.encode())
            obtained = protocol.obtain(rec_sk, issuer_keys.public_key, psig, message_str.encode())
        
        if obtained:
            hanzlik_m_point, sig_tuple = obtained
            signature_data = to_dict(sig_tuple)
    elif scheme_name == "Fischlin":
        request, user_state = protocol.create_request(message_str.encode(), issuer_keys.encryption_key)
        response = protocol.create_response(request, issuer_keys)
        final_sig = protocol.unblind_signature(response, user_state, issuer_keys.verification_key)
        if final_sig: signature_data = to_dict(final_sig.signature)
    else: # Practical
        user_msg1, user_state = protocol.user_step1(message_str.encode(), issuer_keys)
        signer_msg1, signer_state = protocol.signer_step1(user_msg1, issuer_keys)
        user_msg2 = protocol.user_step2(signer_msg1, user_state, issuer_keys)
        signer_msg2 = protocol.signer_step2(user_msg2, signer_state, issuer_keys)
        final_sig = protocol.user_finalize(signer_msg2, user_state)
        if final_sig: signature_data = to_dict(final_sig)

    issued_msg = IssuedMessage(serial_number, message_content, signature_data, tag, hanzlik_m_point)
    print("✓ Issuance successful.")

    # --- Verification ---
    def verify_message(c: IssuedMessage, is_forgery_test: bool = False, forged_m_point: Optional[tuple] = None):
        print(f"\n>>> Verifying message '{c.message}' <<<")
        
        verify_str = MESSAGE_FORMAT.format(serial_number=c.serial_number, message=c.message)
        is_valid = False
        
        try:
            if "Hanzlik" in scheme_name:
                sig_parts = c.signature
                reconstructed_sig = [
                    tuple(FQ(coord) for coord in sig_parts[0]),
                    tuple(FQ(coord) for coord in sig_parts[1]),
                    tuple(FQ2(coords) for coords in sig_parts[2]),
                ]
                if "Tagged" in scheme_name:
                    reconstructed_sig.append(tuple(FQ2(coords) for coords in sig_parts[3]))
                sig = tuple(reconstructed_sig)

                m_to_verify = forged_m_point if is_forgery_test else c.hanzlik_m_point
                
                if "Tagged" in scheme_name:
                    is_valid = protocol.verify(issuer_keys.public_key, m_to_verify, c.tag, sig)
                else:
                    is_valid = protocol.verify(issuer_keys.public_key, m_to_verify, sig)
            elif scheme_name == "Fischlin":
                sig_obj = UnblindedSignature(signature=c.signature, message=verify_str.encode())
                is_valid = protocol.verify_signature(sig_obj, issuer_keys.verification_key)
            elif scheme_name == "Practical":
                sig_data_as_tuples = lists_to_tuples(c.signature)
                sig_obj = KRWFinalSignature(**sig_data_as_tuples)
                is_valid = protocol.verify(verify_str.encode(), sig_obj, issuer_keys)
        except Exception as e:
            print(f"  - Verification threw an exception: {e}")
            is_valid = False

        if is_forgery_test:
            print(f"  - RESULT: {'[✅ PASS] Forgery correctly detected!' if not is_valid else '[❌ FAIL] Forgery was accepted!'}")
        else:
            print(f"  - RESULT: {'[✅ VALID]' if is_valid else '[❌ INVALID]'}")
    
    # 1. Verify the original, valid message
    verify_message(issued_msg)

    # 2. Attempt a forgery
    print("\n" + "-"*20 + " FORGERY ATTEMPT " + "-"*20)
    if "Hanzlik" in scheme_name:
        # FIX: Call the imported 'multiply' function directly.
        forged_m_point = multiply(protocol.g1, secrets.randbelow(protocol.order))
        verify_message(issued_msg, is_forgery_test=True, forged_m_point=forged_m_point)
    else:
        forged_message_content = "FORGED MESSAGE"
        forged_serial_number = secrets.token_hex(16)
        forged_msg = IssuedMessage(
            serial_number=forged_serial_number,
            message=forged_message_content,
            signature=issued_msg.signature,
            tag=issued_msg.tag
        )
        verify_message(forged_msg, is_forgery_test=True)


def main():
    display_config()
    run_demo("Fischlin", "School Fee")
    run_demo("Practical", "Medical Fee")
    run_demo("Hanzlik", "Rent Fee")
    run_demo("Hanzlik (Tagged)", "Lottery Ticket", tag=b"Round-July-2025")
    print("\n" + "="*60)
    print("All demonstrations complete.")
    return 0

if __name__ == "__main__":
    main()