__author__ = 'adz'


'''first attempt at a results object / class'''



class Results:
    def __init__(self, target, port, **kwargs):
        self.target = target
        self.port = port



class SslyzeResults(Results):

    def printlines(self, version, issue, cipher, keysize):
        return "[%s] issue found : %s with cipher %s of keylength %s" % (version, issue, cipher, keysize)

    def printfindings(self):

        print "=================REPORT BELOW===============" \
              "\n[i] Data for host : %s : %s" % (self.target, self.port)

        print "[h] HeartBleed found : %s " % self.heartbleed
        if self.additionalcertinfo:
            print "[A] Aditional cert information"
            if self.addressvalue:
                print "[A] %s" % self.addressvalue
            if self.certlistentry:
                print "[A] DNScertName %s" % self.certlistentry
            if self.expiry:
                print "[A] Expiry date %s" % self.expiry

        print "[i] SSL v2 Findings below"
        for finding in self.sslv2findings:
            print self.printlines('SSLv2', finding['issue'], finding['cipher'], finding['keysize'])
        print "[i] SSL v3 Findings below"
        for finding in self.sslv3findings:
            print self.printlines('SSLv3', finding['issue'], finding['cipher'], finding['keysize'])
        print "[i] TLS v1.0 Findings below"
        for finding in self.tls1findings:
            print self.printlines('TLS1.0', finding['issue'], finding['cipher'], finding['keysize'])
        print "[i] TLS v1.1 Findings below"
        for finding in self.tls1_1findings:
            print self.printlines('TLS1.1', finding['issue'], finding['cipher'], finding['keysize'])
        print "[i] TLS v1.2 Findings below"
        for finding in self.tls1_2findings:
            print self.printlines('TLS1.2', finding['issue'], finding['cipher'], finding['keysize'])

    def addsslv3result(self, issue, cipher, keysize):
        finding = {'issue': issue, 'cipher': cipher, 'keysize': keysize}
        self.sslv3findings.append(finding)

    def addsslv2result(self, issue, cipher, keysize):
        finding = {'issue': issue, 'cipher': cipher, 'keysize': keysize}
        self.sslv2findings.append(finding)

    def addtls1result(self, issue, cipher, keysize):
        finding = {'issue': issue, 'cipher': cipher, 'keysize': keysize}
        self.tls1findings.append(finding)

    def addtls1_1result(self, issue, cipher, keysize):
        finding = {'issue': issue, 'cipher': cipher, 'keysize': keysize}
        self.tls1_1findings.append(finding)

    def addtls1_2result(self, issue, cipher, keysize):
        finding = {'issue': issue, 'cipher': cipher, 'keysize': keysize}
        self.tls1_2findings.append(finding)

    def __init__(self, target, port, heartbleed, **kwargs):
        self.sslv2findings = []
        self.sslv3findings = []
        self.tls1findings = []
        self.tls1_1findings = []
        self.tls1_2findings = []
        self.results = []
        self.target = target
        self.port = port
        self.heartbleed = heartbleed

        for key, value in kwargs.iteritems():
            if key == "addressvalue":
                self.addressvalue = value
                self.additionalcertinfo=True
            if key == "certlistentry":
                self.certlistentry = value
                self.additionalcertinfo=True
            if key == "expires":
                self.expiry = value
                self.additionalcertinfo=True





