import json, binascii, os
from gostcrypto import gostsignature as gs
from gostcrypto import gosthash

WS = os.path.dirname(os.path.abspath(__file__))


def h256(msg):
    h = gosthash.new('streebog256')
    h.update(msg)
    return h.digest()


def h512(msg):
    h = gosthash.new('streebog512')
    h.update(msg)
    return h.digest()


curve = gs.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-2012-256-paramSetA']
print("curve keys:", list(curve.keys()))
out = {}
out['curve'] = {k: (v.hex() if isinstance(v, (bytes, bytearray)) else v)
                for k, v in curve.items() if k != 'oid'}

sig = gs.new(gs.MODE_256, curve)

vectors = []
privs = [
    '2A929ADEB6F5A3C0E26C3D981D34E0F9463FEC5A4D0C3B6F3E0D8F7A928937C1',
    '0000000000000000000000000000000000000000000000000000000000000001',
    '3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0FD8CDDFC87B6635C115AF556C360C66',
    '1902D60CE9A1E1BE5F2E4C5E1B7F9A8C3D5E6F708192A3B4C5D6E7F8091A2B3C',
]
randks = [
    '1A929ADEB6F5A3C0E26C3D981D34E0F9463FEC5A4D0C3B6F3E0D8F7A928937C1',
    '0000000000000000000000000000000000000000000000000000000000000002',
    '3000000000000000000000000000000000000000000000000000000000000003',
    '112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00',
]
msgs = [
    b'',
    b'Test message',
    b'\x01\x02\x03\x04\x05',
    bytes(range(64)),
    b'The quick brown fox jumps over the lazy dog',
]

for i in range(4):
    pk = bytes.fromhex(privs[i])
    rk = bytes.fromhex(randks[i])
    msg = msgs[i % len(msgs)]
    digest = h256(msg)
    pub = sig.public_key_generate(pk)
    s = sig.sign(pk, digest, rk)
    ok = sig.verify(pub, digest, s)
    bad = bytearray(s)
    bad[0] ^= 0xFF
    try:
        ok_bad = sig.verify(pub, digest, bytes(bad))
    except Exception:
        ok_bad = False
    vectors.append({
        'priv': pk.hex(),
        'pub': bytes(pub).hex(),
        'msg': binascii.hexlify(msg).decode(),
        'digest': digest.hex(),
        'rand_k': rk.hex(),
        'sig': bytes(s).hex(),
        'verify': ok,
        'verify_tampered': ok_bad,
        'streebog512': h512(msg).hex(),
    })
    print(f"vec {i}: verify={ok} tampered={ok_bad} siglen={len(s)} publen={len(pub)}")

out['vectors'] = vectors
with open(os.path.join(WS, 'gost_kat.json'), 'w') as f:
    json.dump(out, f, indent=1)
print("saved gost_kat.json")
