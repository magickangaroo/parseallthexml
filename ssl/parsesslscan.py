__author__ = 'adz'
import sys
import re
if __name__ == "__main__":
    with open(sys.argv[1], 'r') as f:
        data = f.readlines()

    target = ""
    idata = iter(data)
    lowbits = 128
    sslv3 = []
    sslv2 = []
    for line in idata:
        if "Testing SSL server" in line:
            target = "%s (tcp/%s)" % (line.split()[3], line.split()[6])
            print "[T] testing %s" % target

        if "Deflate Compression" in line:
            if "VULNERABLE - Server supports Deflate compression" in idata.next():
                print "[b] Zlib support - likely BEAST/Crime"

        regex = '^NULL|^EXPORT|^EXP|^DES-CBC-|-DES-CBC-|^SEED|^RC4'
        exclude = ["Exponent", "timeout", "error", "IOError"]



        try:
            if "Accepted" in line:

                splitline = line.split()
                if len(splitline) > 0:
                    cipher, length, proto = splitline[-1], splitline[-3], splitline[-4]

                    #print "[i] Found %s %s %s" % (length, proto, cipher)
                    if int(length) < lowbits:
                        print "[!] Found Low Bits %s Length(%s) Proto(%s) Cipher(%s)" % (target, length, proto, cipher)
                    if proto == "SSLv3":
                        sslv3.append(cipher)
                    if re.search(regex, cipher, re.IGNORECASE):
                        print "[!] Found Bad Cipher %s Length(%s) Proto(%s) Cipher(%s)" \
                              % (target, length, proto, cipher)

        except ValueError:
                continue

    if len(sslv3) > 0:
        print "[SSLV3] Found %s " % sslv3

    if len(sslv2) > 0:
        print "[SSLV2] Found %s " % sslv3
