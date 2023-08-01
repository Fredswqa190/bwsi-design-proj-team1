import struct

class Packet:

    def __init__(self, data):
        self.data = data

    def stream(self):
        for number, idx in enumerate(range(0, len(self.data), 2) ,1):
            data = self.data[idx:idx+2]
            s = '>ii{}s'.format(len(data))
            yield struct.pack(s, number, len(data), data)

data = open("/home/jovyan/work/bwsi-design-proj-team1/firmware/gcc/main.bin", 'rb').read()  

p = Packet(data=data)

writer = open ("hi.txt", 'w')

for item in p.stream():
    writer.write(str(item)[2:-1])
    print(item)