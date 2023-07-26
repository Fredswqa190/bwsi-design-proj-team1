from Crypto.PublicKey import ECC

key = ECC.generate(curve='P-256')
f = open('secret_build_output.txt','wt')
#pub = open('secret_build_output.txt','wt')
f.write(key.export_key(format='PEM'))
f.write("\n")
f.write(key.public_key().export_key(format='PEM'))
#f.close()

#f = open('secret_build_output.txt','rt')

#privkey = ECC.import_key(f.read())