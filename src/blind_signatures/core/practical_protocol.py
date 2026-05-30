"""
Core implementation of the interactive signature scheme from "Practical Blind
Signatures in Pairing-Free Groups" by Klooß, Reichle, and Wagner (2024).
"""
from typing import Tuple, Dict, Any, Optional
from dataclasses import dataclass
import secrets
from py_ecc.secp256k1 import secp256k1
from hashlib import sha256
from ..utils.hash_utils import hash_to_scalar


# --- Protocol-Specific Data Structures ---
@dataclass
class KRW_SignerKeys:
    secret_key_u: int
    public_key_U: Tuple[int, int]
    H: Tuple[int, int]
    V: Tuple[int, int]
    D1: Tuple[int, int]

@dataclass
class UserStep1_Message:
    C: Tuple[int, int]
    pi_ped: Dict[str, Any]

@dataclass
class SignerStep1_Message:
    T: Tuple[Tuple[int, int], Tuple[int, int], Tuple[int, int]]
    A0: Tuple[Tuple[int, int], Tuple[int, int], Tuple[int, int]]
    A1: Tuple[Tuple[int, int], Tuple[int, int]]

@dataclass
class UserStep2_Message:
    c: int

@dataclass
class SignerStep2_Message:
    z0: Tuple[int, int]
    z1: int
    c0: int

@dataclass
class FinalSignature:
    C: Tuple[int, int]
    S: Tuple[Tuple[int, int], Tuple[int, int], Tuple[int, int]]
    pi: Dict[str, Any]


# --- Core Protocol Class ---
class KlooReichleWagnerSignature:
    """Implements the BBSig interactive signature protocol."""
    def __init__(self):
        self.curve = secp256k1
        self.order = self.curve.N
        self.G = self.curve.G

    def _derive_tau(self, C: Tuple[int, int], m_bar: int) -> bytes:
        """
        Derive a per-message tag τ = H("KRS-Tau" ∥ C ∥ m_bar).
        """
        # encode C and m_bar as big-endian bytes
        c_bytes = C[0].to_bytes(32, 'big') + C[1].to_bytes(32, 'big')
        m_bytes = m_bar.to_bytes((m_bar.bit_length() + 7)//8 or 1, 'big')
        return sha256(b'KRS-Tau' + c_bytes + m_bytes).digest()


    def _H_ddh(self, tau: bytes) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        """Random-oracle H_ddh instantiated via hash_to_scalar."""
        d2 = hash_to_scalar(b'H_ddh_D2', self.order, tau)
        d3 = hash_to_scalar(b'H_ddh_D3', self.order, tau)
        return (
            self.curve.multiply(self.G, d2),
            self.curve.multiply(self.G, d3),
        )

    def _prove_pedersen(self, U, C, m, t):
        """NIZK proof of Pedersen commitment opening."""
        r_m = secrets.randbelow(self.order)
        r_t = secrets.randbelow(self.order)
        A = self.curve.add(
            self.curve.multiply(U, r_m),
            self.curve.multiply(self.G, r_t)
        )
        c = hash_to_scalar(b'PedersenProof', self.order, U, self.G, C, A)
        z_m = (r_m + c * m) % self.order
        z_t = (r_t + c * t) % self.order
        return {'A': A, 'z_m': z_m, 'z_t': z_t}

    def _verify_pedersen(self, U, C, proof):
        A, z_m, z_t = proof['A'], proof['z_m'], proof['z_t']
        c = hash_to_scalar(b'PedersenProof', self.order, U, self.G, C, A)
        lhs = self.curve.add(
            self.curve.multiply(U, z_m),
            self.curve.multiply(self.G, z_t)
        )
        rhs = self.curve.add(A, self.curve.multiply(C, c))
        return lhs == rhs

    def keygen(self) -> KRW_SignerKeys:
        u = secrets.randbelow(self.order)
        U = self.curve.multiply(self.G, u)
        H = self.curve.multiply(self.G, secrets.randbelow(self.order))
        V = self.curve.multiply(self.G, secrets.randbelow(self.order))
        D1 = self.curve.multiply(self.G, secrets.randbelow(self.order))
        return KRW_SignerKeys(u, U, H, V, D1)

    # --- Protocol Steps ---
    def user_step1(self, m: bytes, signer_pk: KRW_SignerKeys):
        U = signer_pk.public_key_U
        m_bar = hash_to_scalar(b'MessageHash', self.order, m)
        t = secrets.randbelow(self.order)
        C = self.curve.add(
            self.curve.multiply(U, m_bar),
            self.curve.multiply(self.G, t)
        )
        pi_ped = self._prove_pedersen(U, C, m_bar, t)
        return UserStep1_Message(C, pi_ped), {'m_bar': m_bar, 't': t, 'C': C}

    def signer_step1(self, msg: UserStep1_Message, keys: KRW_SignerKeys):
        if not self._verify_pedersen(keys.public_key_U, msg.C, msg.pi_ped):
            return None, None
        
        s_star = secrets.randbelow(self.order)
        XC = self.curve.add(msg.C, keys.H)
        
        T_star1 = self.curve.add(self.curve.multiply(keys.V, keys.secret_key_u), self.curve.multiply(XC, s_star))
        T_star2 = self.curve.multiply(self.G, s_star)
        T_star = (T_star1, T_star2, keys.public_key_U)

        r0_s, r0_u = secrets.randbelow(self.order), secrets.randbelow(self.order)
        A0_1 = self.curve.add(self.curve.multiply(keys.V, r0_u), self.curve.multiply(XC, r0_s))
        A0_2 = self.curve.multiply(self.G, r0_s)
        A0_3 = self.curve.multiply(self.G, r0_u)
        A0 = (A0_1, A0_2, A0_3)

        r1_d2 = secrets.randbelow(self.order)
        A1_1 = self.curve.multiply(self.G, r1_d2)
        A1_2 = self.curve.multiply(keys.D1, r1_d2)
        A1 = (A1_1, A1_2)

        signer_state = {"s_star": s_star, "u": keys.secret_key_u, "r0_s": r0_s, "r0_u": r0_u}
        return SignerStep1_Message(T=T_star, A0=A0, A1=A1), signer_state

    def user_step2(self, msg: SignerStep1_Message, user_state: Dict, signer_pk: KRW_SignerKeys):
        T_star, A0_C, A1 = msg.T, msg.A0, msg.A1
        C, t, m_bar = user_state["C"], user_state["t"], user_state["m_bar"]

        term_to_subtract_S = self.curve.multiply(T_star[1], t)
        S1 = self.curve.add(T_star[0], self.curve.multiply(term_to_subtract_S, self.order - 1))
        S = (S1, T_star[1], signer_pk.public_key_U)

        term_to_subtract_A0 = self.curve.multiply(A0_C[1], t)
        A0_1_new = self.curve.add(A0_C[0], self.curve.multiply(term_to_subtract_A0, self.order - 1))
        A0 = (A0_1_new, A0_C[1], A0_C[2])

        tau = self._derive_tau(C, m_bar)
        c = hash_to_scalar(b'FinalChallenge', self.order, S, A0, A1, m_bar, tau)
        user_state.update({'S': S, 'A0': A0, 'c': c, "A1": A1, 'tau': tau})
        return UserStep2_Message(c=c)

    def signer_step2(self, msg: UserStep2_Message, signer_state: Dict, keys: KRW_SignerKeys):
        c1 = secrets.randbelow(self.order)
        c0 = (msg.c - c1) % self.order
        
        s_star, u, r0_s, r0_u = signer_state["s_star"], signer_state["u"], signer_state["r0_s"], signer_state["r0_u"]

        z0_s = (r0_s + c0 * s_star) % self.order
        z0_u = (r0_u + c0 * u) % self.order

        z1 = secrets.randbelow(self.order)
        
        return SignerStep2_Message(z0=(z0_s, z0_u), z1=z1, c0=c0)

    def user_finalize(self, msg: SignerStep2_Message, user_state: Dict):
        pi = {
            "A0": user_state["A0"], 
            "A1": user_state["A1"],
            'c': user_state['c'],
            "c0": msg.c0, 
            "z0": msg.z0, 
            "z1": msg.z1
        }
        return FinalSignature(C=user_state["C"], S=user_state["S"], pi=pi)

    def verify(self, m: bytes, sig: FinalSignature, signer_pk: KRW_SignerKeys) -> bool:
        """Full cryptographic verification of the BBSig signature."""
        S, pi = sig.S, sig.pi
        A0, A1, c0, z0, z1 = pi["A0"], pi["A1"], pi["c0"], pi["z0"], pi["z1"]
        
        m_bar = hash_to_scalar(b'MessageHash', self.order, m)
        tau   = self._derive_tau(sig.C, m_bar)
        mU = self.curve.multiply(signer_pk.public_key_U, m_bar)

        X = self.curve.add(mU, signer_pk.H)

        c_prime = hash_to_scalar(b'FinalChallenge', self.order, S, A0, A1, m_bar, tau)
        c1 = (c_prime - c0) % self.order

        # Verify Branch 0 (Signature Path)
        z0_s, z0_u = z0
        S1, S2, U = S
        A0_1, A0_2, A0_3 = A0
        
        lhs1 = self.curve.add(self.curve.multiply(signer_pk.V, z0_u), self.curve.multiply(X, z0_s))
        rhs1 = self.curve.add(A0_1, self.curve.multiply(S1, c0))
        
        lhs2 = self.curve.multiply(self.G, z0_s)
        rhs2 = self.curve.add(A0_2, self.curve.multiply(S2, c0))
        
        lhs3 = self.curve.multiply(self.G, z0_u)
        rhs3 = self.curve.add(A0_3, self.curve.multiply(U, c0))
        
        check0 = (lhs1 == rhs1) and (lhs2 == rhs2) and (lhs3 == rhs3)
        
        # Verify Branch 1 (DDH Path)
        A1_1, A1_2 = A1
        D2, D3 = self._H_ddh(tau)

        check1_lhs1 = self.curve.multiply(self.G, z1)
        check1_rhs1 = self.curve.add(A1_1, self.curve.multiply(D2, c1))

        check1_lhs2 = self.curve.multiply(signer_pk.D1, z1)
        check1_rhs2 = self.curve.add(A1_2, self.curve.multiply(D3, c1))

        check1 = (check1_lhs1 == check1_rhs1) and (check1_lhs2 == check1_rhs2)

        return check0 or check1