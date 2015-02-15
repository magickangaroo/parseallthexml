__author__ = 'adz'


from classes.results import Results
import sqlite3
import uuid
import math


class NessusResults(Results):
    def __init__(self, target, port, guids, tester, logging,  **kwargs):
        self.selfsignedcert = []

        self.target = target
        self.port = port

        self.guids = guids
        self.tester = tester
        self.findingfound = False
        self.findingtextlist = []

        self.logging = logging
        for key, value in kwargs.iteritems():
            if key == "gluedb":
                self.gluedb = value

    def addselfsignedcertfinding(self, issue, service, excerpt, **kwargs):
        finding = {'issue': issue, 'service': service, 'excerpt': excerpt}
        self.findingfound = True
        self.selfsignedcert = finding

    def createfindingtextelfsignedcert(self):
        findingtext = "The following excerpt confirms the certificate found at the top of the certificate chain " \
                      ":\n\n %s" % (self.selfsignedcert['excerpt'])

        self.findingtext = findingtext

    def insertfindings(self):

        if len(self.selfsignedcert) !=0:
            self.createdbobject()
            self.protocol = "TCP"
            self.createfindingtextelfsignedcert()
            self.insertfinding(findingtitle='Untrusted SSL Certificate',
                               findingguid=self.guids['untrustedsslcert'])

            self.commitdb()