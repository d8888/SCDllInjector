#!/usr/bin/env python
import sys
import codecs

hexlify = codecs.getencoder('hex')

if __name__ == "__main__":
	if len(sys.argv) < 2:
		print("usage: %s file.bin\n" % (sys.argv[0],))
		sys.exit(0)

	shellcode = "\""
	ctr = 1
	maxlen = 15

	for b in open(sys.argv[1], "rb").read():
		#shellcode += "\\x" + hex(b)
		shellcode += "\\x"
		shellcode+="".join('%02x'%b)
		if ctr == maxlen:
			#shellcode += "\" +\n\""
			shellcode += "\" \n\""
			ctr = 0
		ctr += 1
	shellcode += "\""
print(shellcode)