//! ГОСТ Р 34.10-2012 — подпись/проверка (256 бит, paramSetA) + VKO (RFC 7836 §4.3.1).
//!
//! Соглашение о порядке байт (внутренний профиль КР-1): все целые
//! (секретный ключ, хэш, k, r, s, координаты точек) — big-endian 32/64 байта.
//! Подпись = r_be(32) || s_be(32) (64 байта); публичный ключ = X_be || Y_be (64 байта).
//!
//! KAT: gostcrypto (независимая реализация) — crypto/gost/src/kat.rs.

use crate::curve::{AffinePoint, Curve};
use crate::u256::U256;
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GostSignError {
    /// Секретный ключ вне диапазона (0, q).
    InvalidPrivateKey,
    /// Случайное k вне диапазона (0, q).
    InvalidRandom,
    /// r или s = 0 — требуется перегенерация k.
    DegenerateSignature,
    /// Публичный ключ не на кривой / бесконечность / вне подгруппы порядка q.
    InvalidPublicKey,
    /// Подпись не прошла проверку.
    BadSignature,
}

fn be_u256(b: &[u8]) -> U256 {
    assert!(b.len() <= 32);
    let mut a = [0u8; 32];
    a[32 - b.len()..].copy_from_slice(b);
    U256::from_be_bytes(&a)
}

/// Публичный ключ (64 байта X||Y) из секретного (32 байта big-endian).
pub fn public_from_private(priv32: &[u8; 32]) -> Result<[u8; 64], GostSignError> {
    let c = Curve::paramset_a();
    let d = be_u256(priv32);
    if d.is_zero() || d >= c.q {
        return Err(GostSignError::InvalidPrivateKey);
    }
    let q = c.scalar_mul(&d, None);
    Ok(q.to_bytes())
}

/// Детерминированная подпись с заданным k (для KAT).
pub fn sign_deterministic(
    priv32: &[u8; 32],
    digest32: &[u8; 32],
    k32: &[u8; 32],
) -> Result<[u8; 64], GostSignError> {
    let c = Curve::paramset_a();
    let mut d = be_u256(priv32);
    let mut k = be_u256(k32);
    if d.is_zero() || d >= c.q {
        d.zeroize();
        k.zeroize();
        return Err(GostSignError::InvalidPrivateKey);
    }
    if k.is_zero() || k >= c.q {
        d.zeroize();
        k.zeroize();
        return Err(GostSignError::InvalidRandom);
    }

    // α = e mod q; если α = 0 → α = 1
    let mut e = be_u256(digest32);
    e = c.reduce_q(&e);
    if e.is_zero() {
        e = U256::ONE;
    }

    // C = k·P; r = x_C mod q
    let cp = c.scalar_mul(&k, None);
    let mut r = cp.x;
    while r >= c.q {
        let (d2, _) = r.sbb(&c.q, false);
        r = d2;
    }

    // s = (r·d + k·e) mod q
    let mq = &c.mont_q;
    let rd = mq.mul_nat(&r, &d);
    let ke = mq.mul_nat(&k, &e);
    let s = rd.add_mod(&ke, &c.q);

    d.zeroize();
    k.zeroize();

    if r.is_zero() || s.is_zero() {
        return Err(GostSignError::DegenerateSignature);
    }
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r.to_be_bytes());
    sig[32..].copy_from_slice(&s.to_be_bytes());
    Ok(sig)
}

/// Подпись со случайным k (OS-энтропия; production — сертифицированный ГПСЧ, §23.8).
pub fn sign(priv32: &[u8; 32], digest32: &[u8; 32]) -> Result<[u8; 64], GostSignError> {
    loop {
        let mut k = [0u8; 32];
        sakura_common::rand::fill(&mut k);
        k[0] &= 0x3F; // k < 2^254 < q·… приводится; цикл отбрасывает вырожденные
        match sign_deterministic(priv32, digest32, &k) {
            Ok(sig) => {
                k.zeroize();
                return Ok(sig);
            }
            Err(GostSignError::InvalidRandom) | Err(GostSignError::DegenerateSignature) => {
                k.zeroize();
                continue;
            }
            Err(e) => {
                k.zeroize();
                return Err(e);
            }
        }
    }
}

/// Проверка подписи (64 байта r||s) публичным ключом (64 байта X||Y).
pub fn verify(pub64: &[u8; 64], digest32: &[u8; 32], sig64: &[u8; 64]) -> bool {
    match verify_checked(pub64, digest32, sig64) {
        Ok(()) => true,
        Err(_) => false,
    }
}

/// Проверка с явной ошибкой. Полный контроль точки: на кривой, не бесконечность,
/// [q]Q = O (принадлежность подгруппе порядка q).
pub fn verify_checked(
    pub64: &[u8; 64],
    digest32: &[u8; 32],
    sig64: &[u8; 64],
) -> Result<(), GostSignError> {
    let c = Curve::paramset_a();
    let qpt = AffinePoint::from_bytes(pub64);
    if qpt.infinity || !c.is_on_curve(&qpt) {
        return Err(GostSignError::InvalidPublicKey);
    }
    // проверка порядка: [q]Q = O
    let qj = c.affine_to_jac(&qpt);
    let qmul = c.scalar_mul(&c.q, Some(&qj));
    if !qmul.infinity {
        return Err(GostSignError::InvalidPublicKey);
    }

    let r = be_u256(&sig64[..32]);
    let s = be_u256(&sig64[32..]);
    if r.is_zero() || r >= c.q || s.is_zero() || s >= c.q {
        return Err(GostSignError::BadSignature);
    }

    let mut e = be_u256(digest32);
    e = c.reduce_q(&e);
    if e.is_zero() {
        e = U256::ONE;
    }

    let mq = &c.mont_q;
    let e_m = mq.to_mont(&e);
    let v = mq.inv(&e_m); // v = α^{-1} mod q (в Монтгомери-форме)
    let s_m = mq.to_mont(&s);
    let r_m = mq.to_mont(&r);
    let z1 = mq.from_mont(&mq.mul(&s_m, &v));
    let rv = mq.from_mont(&mq.mul(&r_m, &v));
    let z2 = rv.neg_mod(&c.q); // z2 = −r·v mod q

    // C = z1·P + z2·Q
    let p1 = c.scalar_mul(&z1, None);
    let p2 = c.scalar_mul(&z2, Some(&qj));
    let sum = if p1.infinity {
        p2
    } else if p2.infinity {
        p1
    } else {
        c.to_affine(&c.jac_add(&c.affine_to_jac(&p1), &c.affine_to_jac(&p2)))
    };
    if sum.infinity {
        return Err(GostSignError::BadSignature);
    }
    let mut rr = sum.x;
    while rr >= c.q {
        let (d2, _) = rr.sbb(&c.q, false);
        rr = d2;
    }
    if rr == r {
        Ok(())
    } else {
        Err(GostSignError::BadSignature)
    }
}

/// VKO_GOSTR3410_2012_256 (RFC 7836 §4.3.1):
/// KEK = H₂₅₆(K), K = ((m/q)·UKM·x mod q)·(y·P).
/// UKM — 8 байт (64 бита). Координаты точки — big-endian, X||Y (профиль КР-1).
pub fn vko_kek_256(priv_x: &[u8; 32], peer_pub: &[u8; 64], ukm: u64) -> Result<[u8; 32], GostSignError> {
    let c = Curve::paramset_a();
    let x = be_u256(priv_x);
    if x.is_zero() || x >= c.q {
        return Err(GostSignError::InvalidPrivateKey);
    }
    let qpt = AffinePoint::from_bytes(peer_pub);
    if qpt.infinity || !c.is_on_curve(&qpt) {
        return Err(GostSignError::InvalidPublicKey);
    }
    let qj = c.affine_to_jac(&qpt);
    let qmul = c.scalar_mul(&c.q, Some(&qj));
    if !qmul.infinity {
        return Err(GostSignError::InvalidPublicKey);
    }
    let mq = &c.mont_q;
    let mut scalar = mq.mul_nat(&U256::from_u64(c.cofactor), &U256::from_u64(ukm));
    scalar = mq.mul_nat(&scalar, &x);
    let pt = c.scalar_mul(&scalar, Some(&qj));
    if pt.infinity {
        return Err(GostSignError::InvalidPublicKey);
    }
    let mut xy = [0u8; 64];
    xy[..32].copy_from_slice(&pt.x.to_be_bytes());
    xy[32..].copy_from_slice(&pt.y.to_be_bytes());
    Ok(crate::hash::streebog256(&xy))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::streebog256;

    /// Главный KAT: байт-в-байт совпадение с независимой реализацией
    /// gostcrypto (Python) на векторах tools/codegen/gen_kats.py.
    #[test]
    fn kat_gostcrypto_signatures() {
        for v in crate::kat::SIG_VECS {
            let mut privk = [0u8; 32];
            privk.copy_from_slice(&sakura_common::hex::decode(v.priv_).unwrap());
            let msg = sakura_common::hex::decode(v.msg).unwrap();
            let digest = streebog256(&msg);
            // digest совпадает с gostcrypto
            assert_eq!(sakura_common::hex::encode(&digest), v.digest);
            // публичный ключ совпадает
            let pubk = public_from_private(&privk).unwrap();
            assert_eq!(sakura_common::hex::encode(&pubk), v.pub_);
            // детерминированная подпись совпадает БАЙТ-В-БАЙТ
            let mut k = [0u8; 32];
            k.copy_from_slice(&sakura_common::hex::decode(v.rand_k).unwrap());
            let sig = sign_deterministic(&privk, &digest, &k).unwrap();
            assert_eq!(sakura_common::hex::encode(&sig), v.sig, "signature mismatch");
            // проверка принимает, тамперинг отвергает
            let mut sigb = [0u8; 64];
            sigb.copy_from_slice(&sakura_common::hex::decode(v.sig).unwrap());
            assert!(verify(&pubk, &digest, &sigb));
            sigb[63] ^= 0x01;
            assert!(!verify(&pubk, &digest, &sigb));
        }
    }

    #[test]
    fn streebog256_512_kat() {
        for v in crate::kat::SIG_VECS {
            let msg = sakura_common::hex::decode(v.msg).unwrap();
            assert_eq!(sakura_common::hex::encode(&crate::hash::streebog512(&msg)), v.s512);
        }
    }

    #[test]
    fn random_sign_verify_roundtrip() {
        let mut privk = [0u8; 32];
        sakura_common::rand::fill(&mut privk);
        privk[0] &= 0x3F;
        let pubk = public_from_private(&privk).unwrap();
        let d = streebog256(b"control command payload");
        let sig = sign(&privk, &d).unwrap();
        assert!(verify(&pubk, &d, &sig));
        // чужой дайджест не проходит
        let d2 = streebog256(b"tampered payload");
        assert!(!verify(&pubk, &d2, &sig));
    }

    #[test]
    fn invalid_keys_rejected() {
        // d = 0 и d = q недопустимы
        let zero = [0u8; 32];
        assert!(public_from_private(&zero).is_err());
        let mut q = [0u8; 32];
        q.copy_from_slice(&Curve::paramset_a().q.to_be_bytes());
        assert!(public_from_private(&q).is_err());
        // публичный ключ не на кривой
        let mut bad = [0u8; 64];
        bad[0] = 1;
        bad[63] = 2;
        assert!(!verify(&bad, &[7u8; 32], &[9u8; 64]));
    }

    #[test]
    fn vko_shared_secret_symmetry() {
        let mut xa = [0u8; 32];
        let mut xb = [0u8; 32];
        sakura_common::rand::fill(&mut xa);
        sakura_common::rand::fill(&mut xb);
        xa[0] &= 0x3F;
        xb[0] &= 0x3F;
        let pa = public_from_private(&xa).unwrap();
        let pb = public_from_private(&xb).unwrap();
        let ukm = 0x1122334455667788u64;
        let ka = vko_kek_256(&xa, &pb, ukm).unwrap();
        let kb = vko_kek_256(&xb, &pa, ukm).unwrap();
        assert_eq!(ka, kb);
        // другой UKM → другой KEK
        let kc = vko_kek_256(&xa, &pb, ukm ^ 1).unwrap();
        assert_ne!(ka, kc);
    }

    #[test]
    fn zero_digest_maps_to_one() {
        // e = 0 → α = 1 (по стандарту); подпись/проверка не падают
        let mut privk = [1u8; 32];
        privk[0] = 0x01;
        let pubk = public_from_private(&privk).unwrap();
        let d = [0u8; 32];
        let mut k = [2u8; 32];
        k[0] = 0x02;
        let sig = sign_deterministic(&privk, &d, &k).unwrap();
        assert!(verify(&pubk, &d, &sig));
    }
}
