__author__ = 'adz'
import sys
import re
if __name__ == "__main__":
    with open(sys.argv[1], 'r') as f:
        data = f.readlines()


    target = ""
    idata = iter(data)
    badsuiteslist = []
    lowbitslist = []
    lowbits = 128
    beastlist = []
    verbose = False

    for line in idata:
        if "SCAN RESULTS FOR" in line:
            target = line.split()[-1]


        if "Deflate Compression" in line:
            if "VULNERABLE - Server supports Deflate compression" in idata.next():
                if verbose:
                    print "[b] Zlib support - likely BEAST/Crime"
                beastlist.append([target, "Zlib support"])

        regex = '^NULL|^EXPORT|^EXP|^DES-CBC-|-DES-CBC-|^RC4'
        exclude = ["Exponent", "timeout", "error", "IOError"]

        try:
            if len(line) > 0:
                splitline = line.split()
                if len(splitline) > 0:
                    if re.search(regex, splitline[0], re.IGNORECASE):
                        if not any(excludee in line for excludee in exclude):

                            if verbose:
                                print "[*] Found Bad Suite %s %s" % (target, splitline[0])
                            badsuiteslist.append([target, splitline[0]])

                        #if "ClientCertificateRequested" in line:



                splitline = line.split()

                try:
                    if splitline.index("bits"):
                        if splitline.index("bits") == 3:
                            cypherlength = splitline[splitline.index("bits")-1]
                        elif splitline.index("bits") == 2:
                            cypherlength = splitline[splitline.index("bits")+1]

                        if int(cypherlength) < lowbits:
                            if not any(excludee in line for excludee in exclude):
                                if verbose:
                                    print "[*] Found Low Bits %s Length(%s) Cipher(%s)" % \
                                          (target, str(cypherlength), str(splitline[0]))
                                lowbitslist.append([target, str(cypherlength), str(splitline[0])])

                except ValueError:
                    continue

        except ValueError:
                continue


    print "Report Below :"
    results = []
    target = ""
    currentsuites = []

    for i in badsuiteslist:
        targetnow = i[0]

        #print currentsuites
        if targetnow !=  target:
            printthis = "host %s (TCP/%s)" % (targetnow.split(':')[0], targetnow.split(':')[1])
            #print "\nNew Target %s" % printthis
            issues = { 'suites': currentsuites }
            results.append([target, issues])

            target = targetnow
            currentsuites = []

        if i[1] not in currentsuites:
            #print i[1]
            currentsuites.append(i[1])



    target = ""
    currentsuites = []
    #for result in results:
    #    print result


    btargets = 0
    ltargets = 0
    for i in badsuiteslist:
        targetnow = i[0]
        if targetnow !=  target:
            btargets += 1
            printthis = "host %s (TCP/%s)" % (targetnow.split(':')[0], targetnow.split(':')[1])
            print "\nThe identified resource %s was found to support the following cipher-suites with known security issues"\
                  % printthis
            issues = { 'badsuite': currentsuites }


            try:
                index = results.index(target)
                print index
            except ValueError:
                results.append([target, issues])

            target = targetnow
            currentsuites = []
        if i[1] not in currentsuites:
            print "cipher-suite : %s" % (i[1])
            currentsuites.append(i[1])


    for i in lowbitslist:
        targetnow = i[0]
        if targetnow !=  target:
            ltargets += 1
            printthis = "host %s (TCP/%s)" % (targetnow.split(':')[0], targetnow.split(':')[1])
            print "\nThe identified resource %s was found to support the following cipher-suites with low bits " \
                  "(under 128 bit effective)" % printthis

            issues = { 'lowbit': currentsuites }

            #find if target in current list

            try:
                index = results.index(target)
                print index
            except ValueError:
                results.append([target, issues])

            target = targetnow
            currentsuites = []
        if i[2] not in currentsuites:
            print "Suite %s supports %s bits" % (i[2], i[1])
            currentsuites.append(i[2])
        #print "Bits %s Suite %s" % (i[1], i[2])

    print "number of bad suites %s \n number of low bits %s" % (str(btargets), str(ltargets))

'''
    for result in results:
        print result

    #beastlist = []
'''