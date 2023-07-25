from Crypto.PublicKey import ECC

key = ECC.generate(curve='P-256')
f = open('myprivatekey.pem','wt')
pub = open('mypublickey.pem','wt')
f.write(key.export_key(format='PEM'))
f.close()

f = open('myprivatekey.pem','rt')
pub.write(key.public_key().export_key(format='PEM'))
privkey = ECC.import_key(f.read())
