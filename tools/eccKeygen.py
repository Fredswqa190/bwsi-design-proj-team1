from Crypto.PublicKey import ECC

key = ECC.generate(curve='P-256')
f = open('secret_build_output.txt','a')
#pub = open('secret_build_output.txt','wt')

eccPrivKey = key.export_key(format='PEM')
f.write(eccPrivKey)
f.write("\n")
eccPubKey = key.public_key().export_key(format='PEM')
f.write(eccPubKey)
#f.write(key.public_key().export_key(format='PEM'))
#f.close()

#f = open('secret_build_output.txt','rt')

#privkey = ECC.import_key(f.read())