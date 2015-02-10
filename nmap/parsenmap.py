__author__ = 'adz'
import sys
def check(line):
    if "|" in line and "|_" not in line:
        return True
    else:
        return False

if __name__ == "__main__":
    with open(sys.argv[1], 'r') as f:
        data = f.readlines()

    ip = ""
    encryptionlevel = ""
    currentport = ""

    idata = iter(data)

    for line in idata:

        if "Nmap scan report for" in line and "down" not in line:
            ip = line.split()[-1]

        if "open" in line:
            if "/tcp" or "/udp" in line:
                if "/" in line.split()[0]:
                    currentport = line.split()[0]

            if "123" in line:

                if "ntp-monlist" in idata.next():
                    print "%s (%s)" % (ip, currentport)

                    nextline = idata.next()
                    if "Private Clients" in nextline:
                        print "Number of private clients %s" % nextline.split(' ')[-1]
                    nextline = idata.next()
                    if "Private Clients" in nextline:
                        print "Number of private clients %s" % nextline.split(' ')[-1]
                    nextline = idata.next()
                    if "Private Clients" in nextline:
                        print "Number of private clients %s" % nextline.split(' ')[-1]

                    if "Private Clients" in nextline:
                        print "Number of private clients %s" % nextline.split(' ')[-1]
                    nextline = idata.next()
                    if "Private Clients" in nextline:
                        print "Number of private clients %s" % nextline.split(' ')[-1]
                    nextline = idata.next()
                    if "Private Clients" in nextline:
                        print "Number of private clients %s" % nextline.split(' ')[-1]

                    if "Private Clients" in nextline:
                        print "Number of private clients %s" % nextline.split(' ')[-1]
                    nextline = idata.next()
                    if "Private Clients" in nextline:
                        print "Number of private clients %s" % nextline.split(' ')[-1]
                    nextline = idata.next()
                    if "Private Clients" in nextline:
                        print "Number of private clients %s" % nextline.split(' ')[-1]



        if "ssl-poodle:" in line:
            if "VULNERABLE" in idata.next():
                print "[P] found vulnerable poodleservice at %s (%s) " % (ip, currentport)



