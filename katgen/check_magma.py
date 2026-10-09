from gostcrypto import gostcipher
import inspect

kek = bytes.fromhex('a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9')
K   = bytes.fromhex('202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f')
seed = bytes.fromhex('af21434145656378')
print('kek len', len(kek))

c = gostcipher.new('magma', kek, iv=None, mode=gostcipher.MODE_ECB)
enc = bytes(c.encrypt(K))
print('ECB :', enc.hex())
print('want: d15547f8ee85121bc87d4b1027d26027ecc071bba6e72f3fec6f620f56834c5a')

# MAC: GOST34132015mac takes data via new(..., data=...)
m = gostcipher.new('magma', kek, iv=seed, mode=gostcipher.MODE_MAC, data=K)
print('MAC attrs:', [a for a in dir(m) if 'mac' in a.lower() or 'digest' in a.lower()])
for attr in ('mac', 'digest', 'get_mac'):
    if hasattr(m, attr):
        v = getattr(m, attr)
        v = v() if callable(v) else v
        print(f'MAC via {attr}:', bytes(v).hex())
print('want: be33f052')

# inspect magma s-box
src = inspect.getsource(gostcipher.gost_34_12_2015.GOST34122015Magma)
i = src.find('pi')
print(src[:1800])
