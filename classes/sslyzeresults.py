__author__ = 'adz'
from classes.results import Results
import sqlite3
import uuid
import math

class SslyzeResults(Results):

    def printlines(self, version, issue, cipher, keysize):
        return "[%s] issue found : %s with cipher %s of keylength %s" % (version, issue, cipher, keysize)

    def insertfindingtext(self, issue, cipher, keysize):
        return "\tIssue found : %s with cipher %s of keylength %s\n" % (issue, cipher, keysize)

    def printfindings(self):

        if self.findingfound or self.heartbleed == "True":
            print "=================REPORT BELOW===============" \
                  "\n[i] Data for host : %s : %s" % (self.target, self.port)

            if self.heartbleed == "True":
                print "[h] HeartBleed found : %s " % self.heartbleed
            if len(self.sslv2findings) > 0:
                print "[i] SSL v2 Findings below"
                for finding in self.sslv2findings:
                    print self.printlines('SSLv2', finding['issue'], finding['cipher'], finding['keysize'])
            if len(self.sslv3findings) > 0:
                print "[i] SSL v3 Findings below"
                for finding in self.sslv3findings:
                    print self.printlines('SSLv3', finding['issue'], finding['cipher'], finding['keysize'])
            if len(self.tls1findings) > 0:
                print "[i] TLS v1.0 Findings below"
                for finding in self.tls1findings:
                    print self.printlines('TLS1.0', finding['issue'], finding['cipher'], finding['keysize'])
            if len(self.tls1_1findings) > 0:
                print "[i] TLS v1.1 Findings below"
                for finding in self.tls1_1findings:
                    print self.printlines('TLS1.1', finding['issue'], finding['cipher'], finding['keysize'])
            if len(self.tls1_2findings) > 0:
                print "[i] TLS v1.2 Findings below"
                for finding in self.tls1_2findings:
                    print self.printlines('TLS1.2', finding['issue'], finding['cipher'], finding['keysize'])

    def addsslv2result(self, issue, cipher, keysize):
        finding = {'issue': issue, 'cipher': cipher, 'keysize': keysize}
        self.findingfound = True
        self.sslv2findings.append(finding)

    def addsslv3result(self, issue, cipher, keysize):
        finding = {'issue': issue, 'cipher': cipher, 'keysize': keysize}
        self.findingfound = True
        self.sslv3findings.append(finding)

    def addtls1result(self, issue, cipher, keysize):
        finding = {'issue': issue, 'cipher': cipher, 'keysize': keysize}
        self.findingfound = True
        self.tls1findings.append(finding)

    def addtls1_1result(self, issue, cipher, keysize):
        finding = {'issue': issue, 'cipher': cipher, 'keysize': keysize}
        self.findingfound = True
        self.tls1_1findings.append(finding)

    def addtls1_2result(self, issue, cipher, keysize):
        finding = {'issue': issue, 'cipher': cipher, 'keysize': keysize}
        self.findingfound = True
        self.tls1_2findings.append(finding)

    def insertfindings(self):
        self.createdbobject()
        self.createfindingtext()
        self.insertfinding(findingtitle='Insecure SSL Configuration', findingguid=self.guids['insecuresslconfig'])
        self.commitdb()

    def createfindingtext(self):
        if self.findingfound or self.heartbleed == "True":
            #may as well only do this if theres a finding..

            findingtext = "The identified resource host %s (TCP/%s) was found to support the following " \
                          "cipher-suites with known security issues\n\n" % (self.target, self.port)

            if self.heartbleed == "True":
                findingtext += "The HeartBleed vulnerability was found\n"

            '''if self.additionalcertinfo:
                findingtext +=  "[A] Additional cert information"
                if self.addressvalue:
                    findingtext +=  "[A] %s" % self.addressvalue
                if self.certlistentry:
                    findingtext +=  "[A] DNScertName %s" % self.certlistentry
                if self.expiry:
                    findingtext +=  "[A] Expiry date %s" % self.expiry'''
            if len(self.sslv2findings) > 0:
                findingtext += "\nSSL version 2 was found to be in use and supported " \
                               "the following problematic suites:\n"
                for finding in self.sslv2findings:
                    findingtext +=  self.insertfindingtext(finding['issue'], finding['cipher'], finding['keysize'])

            if len(self.sslv3findings) > 0:
                findingtext += "\nSSL version 3 was found to be in use and supported " \
                               "the following problematic suites:\n"
                for finding in self.sslv3findings:
                    findingtext +=  self.insertfindingtext(finding['issue'], finding['cipher'], finding['keysize'])

            if len(self.tls1findings) > 0:
                findingtext += "\nTLS version 1 was found to be in use and supported " \
                               "the following problematic suites:\n"
                for finding in self.tls1findings:
                    findingtext +=  self.insertfindingtext(finding['issue'], finding['cipher'], finding['keysize'])

            if len(self.tls1_1findings) > 0:
                findingtext += "\nTLS version 1 was found to be in use and supported the following problematic suites:\n"
                for finding in self.tls1_1findings:
                    findingtext +=  self.insertfindingtext(finding['issue'], finding['cipher'], finding['keysize'])

            if len(self.tls1_2findings) > 0:
                findingtext += "\nTLS version 1 was found to be in use and supported the following problematic suites:\n"
                for finding in self.tls1_2findings:
                    findingtext +=  self.insertfindingtext(finding['issue'], finding['cipher'], finding['keysize'])

            self.findingtext = findingtext

    def __init__(self, target, port, guids, tester, logging, **kwargs):
        self.sslv2findings = []
        self.sslv3findings = []
        self.tls1findings = []
        self.tls1_1findings = []
        self.tls1_2findings = []
        self.results = []
        self.target = target
        self.port = port
        self.heartbleed = ""
        #guids can be pushed into a config file
        self.guids = guids
        self.tester = tester
        self.findingfound = False
        self.protocol = "TCP"
        self.findingtextlist = []
        self.logging = logging


        for key, value in kwargs.iteritems():
            if key == "gluedb":
                self.gluedb = value
            if key == "addressvalue":
                self.addressvalue = value
                self.additionalcertinfo=True
            if key == "certlistentry":
                self.certlistentry = value
                self.additionalcertinfo=True
            if key == "expires":
                self.expiry = value
                self.additionalcertinfo=True
