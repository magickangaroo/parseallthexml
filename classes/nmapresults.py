__author__ = 'adz'
from classes.results import Results
import sqlite3
import uuid
import math

class nmapResults(Results):
    def __init__(self, target, port, guids, tester, logging, **kwargs):

        #Finding Vars
        self.uneccessaryfinding = []
        self.dospossiblefinding = []
        self.uneccessaryhttpfinding = []
        self.ntpmonlistfinding = []
        self.weakrdpfinding = []
        self.weaksshfinding = []
        #target /results vars
        self.results = []
        self.target = target
        self.port = port

        self.guids = guids
        self.tester = tester
        self.findingfound = False
        self.findingtext = ""
        self.findingtextlist = []
        self.protocol = ""
        self.logging = logging

        for key, value in kwargs.iteritems():
            if key == "gluedb":
                self.gluedb = value

    def addweakrdpfinding(self, issue, service, excerpt, **kwargs):
        finding = {'issue': issue, 'service': service, 'excerpt': excerpt}
        self.findingfound = True
        self.weakrdpfinding = finding

    def addweaksshfinding(self, issue, service, excerpt, **kwargs):
        finding = {'issue': issue, 'service': service, 'excerpt': excerpt}
        self.findingfound = True
        self.weaksshfinding.append(finding)

    def adduneccessaryhttpfinding(self, issue, service, excerpt, **kwargs):
        for key, value in kwargs.iteritems():
            if key == "riskymethods":
                riskymethods = value
                finding = {'issue': issue, 'service': service, 'excerpt': excerpt, 'riskymethod': riskymethods}
                self.findingfound = True
                self.uneccessaryhttpfinding = finding

    def adduneccessaryfinding(self, issue, service, excerpt, **kwargs):

        for key, value in kwargs.iteritems():
            if key == "numberofclients":
                numberofclients = value
                finding = {'issue': issue, 'service': service, 'numberofclients': numberofclients, 'excerpt': excerpt}

                self.findingfound = True
                self.uneccessaryfinding = finding


    def addntpmonlist(self, excerpt):

        finding = {'issue': 'responds to ntp-mon', 'excerpt': excerpt}
        self.findingfound = True
        self.ntpmonlistfinding = finding


    def createfindingtextuneccessary(self):
        findingtext = "The number of private clients reported using NTP monlist, indicates that only %s of " \
                      "ip's have used this service.  This indicates that the service may not be necessary on" \
                      " this host, and could be used to further an attack.\n" % \
                      (self.uneccessaryfinding['numberofclients'])

        if len(self.uneccessaryfinding['excerpt']) > 0:

            findingtext += "The below is a supporting nmap excerpt:\n"
            for excerpt in self.uneccessaryfinding['excerpt']:
                findingtext += excerpt  + "\n"

        self.findingtext = findingtext

    def createfindingtextntpmon(self):
        findingtext = "The NTP monlist command was honoured on this host.\n"

        length = len(self.ntpmonlistfinding['excerpt'])
        '''
        twentypercent = length * 0.5
        roundedupint = int(math.ceil(twentypercent))
        '''
        if len(self.ntpmonlistfinding['excerpt']) > 1:

            findingtext += "The below is a supporting nmap excerpt:\n"
            for line in self.ntpmonlistfinding['excerpt']:
                findingtext += line + "\n"

        self.findingtext = findingtext

    def createfindingtexthttpmethodfinding(self):
        findingtext = "The following nmap excerpt confirms advertised support for the following risky " \
                      "methods : %s\n\n %s" % (self.uneccessaryhttpfinding['riskymethod'].lower(),
                                              self.uneccessaryhttpfinding['excerpt'])
        self.findingtext = findingtext

    def createfindingtexteweakrdp(self):
        findingtext = "The following nmap excerpt confirms the support of weak ciphersuites for the identifed host" \
                      " : \n\n %s" % (self.weakrdpfinding['excerpt'])
        self.findingtext = findingtext

    def createfindingtexteweakssh(self,idx):

        if self.weaksshfinding[idx]['issue'] == "Weak SSH cipher supported":

            findingtext = "The following nmap excerpt confirms the support of weak ssh ciphersuites for the " \
                          "identifed host:\n%s\n" % (self.weaksshfinding[idx]['excerpt'])

            self.findingtextlist.append(findingtext)

        elif self.weaksshfinding[idx]['issue'] == "Weak SSH HMAC supported":
            evidence = ""
            listofevidence = ["hmac-md5", "hmac-sha1-96", "mac_algorithms"]
            for line in self.weaksshfinding[idx]['excerpt'].split('\n'):
                if any(mac in line for mac in listofevidence):
                    evidence += line + "\n"
            findingtext = "The following nmap excerpt confirms the support of weak HMAC support for the identifed host" \
                          " : \n\n %s" % (evidence)

            self.findingtextlist.append(findingtext)

    def insertfindings(self):

        if len(self.weaksshfinding) !=0:
            self.protocol = "TCP"
            for idx, val in enumerate(self.weaksshfinding):
            #for each in self.weaksshfinding:
                self.createdbobject()
                self.createfindingtexteweakssh(idx)

            self.insertfinding(findingtitle='Weak SSH Ciphers Available to Remote Clients',
                           findingguid=self.guids['sshweakcipher'])
            self.commitdb()

        if len(self.weakrdpfinding) != 0:
            self.createdbobject()
            self.protocol = "TCP"
            self.createfindingtexteweakrdp()
            self.insertfinding(findingtitle='Weak Remote Desktop Protocol (RDP) Ciphers Available to Remote Clients',
                               findingguid=self.guids['rdpweakcipher'])

            self.commitdb()

        if len(self.uneccessaryhttpfinding) != 0:

            self.createdbobject()
            self.protocol = "TCP"
            self.createfindingtexthttpmethodfinding()
            self.insertfinding(findingtitle='Unnecessary HTTP Methods Permitted by Web Server',
                               findingguid=self.guids['unnecessarymethods'])

            self.commitdb()

        if len(self.uneccessaryfinding) != 0:
            self.createdbobject()
            self.protocol = "UDP"
            self.createfindingtextuneccessary()
            self.insertfinding(findingtitle='Potentially Unnecessary Network Services Exposed Remotely',
                               findingguid=self.guids['unnecessaryservice'])
            self.commitdb()

        if len(self.ntpmonlistfinding) != 0:
            self.createdbobject()
            self.createfindingtextntpmon()
            self.protocol = "UDP"
            self.insertfinding(findingtitle='Denial of Service Condition Possible',
                               findingguid=self.guids['dospossible'])
            self.commitdb()