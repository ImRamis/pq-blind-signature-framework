#!/usr/bin/env python3
"""
Dissertation Demo: Anonymous E-Voting System

This script demonstrates a privacy-preserving electronic voting system using
blind signatures. It simulates the entire lifecycle of a vote, from registration
to anonymous tallying, highlighting the separation of duties and the prevention
of common electoral fraud vectors like double-voting and forgery.
"""
import sys
import os
import secrets
from typing import Dict, Optional, Any, Set
from dataclasses import dataclass

# Ensure the main library is in the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.blind_signatures.config import display_config
from src.blind_signatures import (
    FischlinBlindSignature, KlooReichleWagnerSignature, HanzlikNIBS,
    UnblindedSignature
)
from src.blind_signatures.core.practical_protocol import FinalSignature as KRWFinalSignature
from src.blind_signatures.utils.serialization import to_dict
from py_ecc.optimized_bls12_381 import FQ, FQ2

# --- Demo Configuration ---
BALLOT_MESSAGE_FORMAT = "VOTING_BALLOT_2025_SERIAL::{serial_number}"

# --- Data Structures ---
@dataclass
class Voter:
    """Represents a citizen eligible to vote."""
    id: str
    has_been_issued_token: bool = False
    vote_choice: str = ""
    signed_ballot: Optional[Dict[str, Any]] = None
    ballot_serial_number: str = ""
    hanzlik_m_point: Optional[tuple] = None

@dataclass
class Tally:
    """Represents the final vote count."""
    votes: Dict[str, int]
    spent_ballot_serials: Set[str]

# --- Helper function to fix data types after JSON conversion ---
def lists_to_tuples(data: Any) -> Any:
    """Recursively converts lists to tuples in a nested structure."""
    if isinstance(data, list):
        return tuple(lists_to_tuples(item) for item in data)
    if isinstance(data, dict):
        return {key: lists_to_tuples(value) for key, value in data.items()}
    return data

# --- Main Demo Logic ---
def run_voting_demo(scheme_name: str):
    """
    Executes a full voting demonstration for a given blind signature scheme.
    """
    print("\n" + "="*80)
    print(f"--- VOTING DEMONSTRATION: The '{scheme_name}' Protocol ---")
    print("="*80)

    # === 1. SETUP PHASE ===
    print("\n[SETUP] 1. The Registration Authority is setting up the cryptographic system...")
    if scheme_name == "Fischlin":
        protocol = FischlinBlindSignature()
        protocol.setup()
        authority_keys = protocol.signer_keygen()
    elif scheme_name == "Practical":
        protocol = KlooReichleWagnerSignature()
        authority_keys = protocol.keygen()
    else: # Hanzlik
        protocol = HanzlikNIBS()
        sk, pk = protocol.keygen()
        @dataclass
        class HanzlikKeys: secret_key: Any; public_key: Any
        authority_keys = HanzlikKeys(secret_key=sk, public_key=pk)
    print(f"✓ Registration Authority for '{scheme_name}' is online and keys have been generated.")

    voter_db = {"voter-12345": Voter(id="voter-12345", vote_choice="Candidate A")}
    tallying_authority = Tally(votes={"Candidate A": 0, "Candidate B": 0}, spent_ballot_serials=set())
    current_voter = voter_db["voter-12345"]

    # === 2. ISSUANCE PHASE ===
    print(f"\n[ISSUANCE] 2. '{current_voter.id}' requests a ballot from the Registration Authority.")
    if current_voter.has_been_issued_token:
        print(f"  - RESULT: [❌ REJECTED] Voter '{current_voter.id}' has already been issued a token.")
    else:
        print(f"  - Voter is eligible. Starting blind signature protocol...")
        current_voter.ballot_serial_number = secrets.token_hex(16)
        ballot_message = BALLOT_MESSAGE_FORMAT.format(serial_number=current_voter.ballot_serial_number).encode()

        if scheme_name == "Fischlin":
            request, user_state = protocol.create_request(ballot_message, authority_keys.encryption_key)
            response = protocol.create_response(request, authority_keys)
            final_sig = protocol.unblind_signature(response, user_state, authority_keys.verification_key)
            if final_sig: current_voter.signed_ballot = to_dict(final_sig.signature)
        elif scheme_name == "Practical":
            user_msg1, user_state = protocol.user_step1(ballot_message, authority_keys)
            signer_msg1, signer_state = protocol.signer_step1(user_msg1, authority_keys)
            user_msg2 = protocol.user_step2(signer_msg1, user_state, authority_keys)
            signer_msg2 = protocol.signer_step2(user_msg2, signer_state, authority_keys)
            final_sig = protocol.user_finalize(signer_msg2, user_state)
            if final_sig: current_voter.signed_ballot = to_dict(final_sig)
        else: # Hanzlik
            rec_sk, rec_pk = protocol.rkeygen()
            psig = protocol.issue(authority_keys.secret_key, rec_pk, ballot_message)
            obtained = protocol.obtain(rec_sk, authority_keys.public_key, psig, ballot_message)
            if obtained:
                current_voter.hanzlik_m_point, sig_tuple = obtained
                current_voter.signed_ballot = to_dict(sig_tuple)

        if current_voter.signed_ballot:
            current_voter.has_been_issued_token = True
            print("✓ Issuance successful. The voter has received an unblinded, signed ballot.")
        else:
            print("  - RESULT: [❌ FAILED] The blind signature protocol failed.")

    # === 3. VOTING & TALLYING PHASE ===
    def cast_vote(voter: Voter, tally: Tally, is_forgery_test: bool = False):
        print(f"\n>>> Submitting ballot with serial '{voter.ballot_serial_number[:10]}...' for vote '{voter.vote_choice}' <<<")

        if not is_forgery_test and voter.ballot_serial_number in tally.spent_ballot_serials:
            print("  - RESULT: [❌ REJECTED (Double-Voting Attempt)]")
            return

        verify_message = BALLOT_MESSAGE_FORMAT.format(serial_number=voter.ballot_serial_number).encode()
        is_valid = False
        try:
            if scheme_name == "Fischlin":
                sig_obj = UnblindedSignature(signature=voter.signed_ballot, message=verify_message)
                is_valid = protocol.verify_signature(sig_obj, authority_keys.verification_key)
            elif scheme_name == "Practical":
                sig_data_as_tuples = lists_to_tuples(voter.signed_ballot)
                sig_obj = KRWFinalSignature(**sig_data_as_tuples)
                is_valid = protocol.verify(verify_message, sig_obj, authority_keys)
            else: # Hanzlik
                sig_parts = voter.signed_ballot
                reconstructed_sig = (
                    tuple(FQ(coord) for coord in sig_parts[0]),
                    tuple(FQ(coord) for coord in sig_parts[1]),
                    tuple(FQ2(coords) for coords in sig_parts[2]),
                )
                is_valid = protocol.verify(authority_keys.public_key, voter.hanzlik_m_point, reconstructed_sig)
        except Exception:
            is_valid = False

        if is_valid:
            print(f"  - RESULT: {'[✅ VALID SIGNATURE]' if not is_forgery_test else '[❌ FAIL] Forgery was accepted!'}")
            if not is_forgery_test:
                tally.spent_ballot_serials.add(voter.ballot_serial_number)
                tally.votes[voter.vote_choice] += 1
        else:
            print(f"  - RESULT: {'[❌ INVALID SIGNATURE]' if not is_forgery_test else '[✅ PASS] Forgery correctly detected!'}")

    # 1. Cast a valid vote
    cast_vote(current_voter, tallying_authority)

    # 2. Attempt to double-vote
    print(f"\n[FRAUD] Voter '{current_voter.id}' attempts to cast their ballot a second time.")
    cast_vote(current_voter, tallying_authority)

    # 3. Attempt to forge a ballot
    print(f"\n[FRAUD] A malicious user attempts to submit a forged ballot.")
    forged_voter = Voter(id="malicious-actor", vote_choice="Candidate A", ballot_serial_number="forged-serial")
    if scheme_name == "Fischlin":
        forged_voter.signed_ballot = {"R": (1, 2), "s": 3}
    elif scheme_name == "Practical":
        forged_voter.signed_ballot = {"C": (1, 2), "S": ((1, 2), (3, 4), (5, 6)), "pi": {"A0": 1, "A1": 2, "c": 3, "c0": 4, "z0": 5, "z1": 6}}
    else: # Hanzlik
        forged_voter.hanzlik_m_point = (1, 2)
        forged_voter.signed_ballot = [[1, 2], [3, 4], [[5, 6], [7, 8]]]
    cast_vote(forged_voter, tallying_authority, is_forgery_test=True)

    # === 4. FINAL TALLY ===
    print("\n" + "-"*80)
    print("VOTING PERIOD ENDED. FINAL RESULTS:")
    print(f"  - Candidate A: {tallying_authority.votes['Candidate A']} vote(s)")
    print(f"  - Total valid votes cast: {len(tallying_authority.spent_ballot_serials)}")
    print("-" * 80)

def main():
    display_config()
    run_voting_demo("Fischlin")
    run_voting_demo("Practical")
    run_voting_demo("Hanzlik")
    print("\n" + "="*80)
    print("All voting demonstrations complete.")
    return 0

if __name__ == "__main__":
    main()