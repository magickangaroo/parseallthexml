#!/usr/bin/env python
# __author__ = 'adz'
import sys
import re
from classes.sslyzeresults import SslyzeResults
import types
import xml.dom.minidom
from xml.dom.minidom import parse
import argparse
import ConfigParser
import os
import logging
from common.common import loggingobject

def getguids(config):
    #grab the guid section, convert from list of tuples to a dictionary

    guids = dict(config.items('guids'))
    return guids

def gettester(config):
    value = config.get('testinginfo', 'tester')
    return value

def getbadsuitetext(config):
    value = config.get('writeups', 'badsuitefound')
    return value

def getlowbitsuitetext(config):
    value = config.get('writeups', 'lowbitsfound')
    return value

def getpoodletext(config):
    value = config.get('writeups', 'poodlefound')
    return value

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='This is a parser for sslyze')
    results = []
    target = ""
    lowbits = 128
    beastlist = []
    verbose = False
    badsuiteregex = '^NULL|^EXPORT|^EXP|^DES-CBC-|^-DES-CBC-^|^RC4'

    exclude = ["Exponent", "timeout", "error", "IOError"]
    scan_result = {}

    parser.add_argument('--xml', '-x', help="Wheres the xml at?", required=True)
    parser.add_argument('--gdb', '-g', help="Wheres the glue at?", required=False)
    parser.add_argument('--cfg', '-c', help="any config file?", required=True)
    parser.add_argument('--log', '-l', help="any log file? defaults to logs/ssylzerxml.log",
                        required=False, default='logs/sslyzerxml.log')
    args = parser.parse_args()

    loggingobject(args, logging)
    logging.info('Starting run now.')


    if args.cfg:
        config = ConfigParser.ConfigParser()
        config.read([os.path.expanduser(args.cfg)])
        #verbosity = config.get('settings', 'verbosity')


    dom = parse(args.xml)

    if args.gdb:
        gluedb = args.gdb
    else:
        gluedb = False

    #Get info out of config
    guids = getguids(config)
    tester = gettester(config)
    badsuitetext = getbadsuitetext(config)
    lowbittext = getlowbitsuitetext(config)
    poodletext = getpoodletext(config)

    for host in dom.getElementsByTagName('target'):
        expires = ""
        addressvalue = ""
        heartbleed = False



        addressvalue = host.getAttributeNode('host').value
        ip = host.getAttributeNode('ip').value
        port = host.getAttributeNode('port').value

        '''for dname in host.getElementsByTagName('subject'):
            for dcn in dname.getElementsByTagName('commonName'):
                commonName = dcn.firstChild.data
                print commonName

        for validity in host.getElementsByTagName('validity'):
            print validity
            for date in dname.getElementsByTagName('notAfter'):
                print date
                expires = date.firstChild.data
        for dname in host.getElementsByTagName('DNS'):
            for ddns in dname.getElementsByTagName('listEntry'):
                certlistentry = ddns.firstChild.data'''
        # create target object
        target = SslyzeResults(ip, port, guids, tester, gluedb=gluedb)

        #search for heartbleed
        for heartbleedresults in host.getElementsByTagName('heartbleed'):
            try:
                heartbleed = heartbleedresults.getAttributeNode('isVulnerable').value
            except Exception:
                continue
        #set hearbleed state
        target.heartbleed = heartbleed
        #itterate through ssl v2 results, adds finding if any suites accepted
        for sslv2results in host.getElementsByTagName('sslv2'):
            for acceptedsslv2 in sslv2results.getElementsByTagName('acceptedCipherSuites'):
                for suite in acceptedsslv2.getElementsByTagName('cipherSuite'):
                    ciphersuite =  suite.getAttributeNode('name').value
                    keysize =  suite.getAttributeNode('keySize').value
                    if re.match(badsuiteregex, ciphersuite):
                        target.addsslv2result(badsuitetext, ciphersuite, keysize)
                    if int(keysize) < lowbits:
                        target.addsslv2result(lowbittext, ciphersuite, keysize)

        #itterate through ssl v3 results, adds finding if any bad suites accepted
        for sslv3results in host.getElementsByTagName('sslv3'):
            for acceptedsslv3 in sslv3results.getElementsByTagName('acceptedCipherSuites'):
                for suite in acceptedsslv3.getElementsByTagName('cipherSuite'):
                    ciphersuite =  suite.getAttributeNode('name').value
                    keysize =  suite.getAttributeNode('keySize').value
                    if re.match(badsuiteregex, ciphersuite):
                        target.addsslv3result(badsuitetext, ciphersuite, keysize)
                    if int(keysize) < lowbits:
                        target.addsslv3result(lowbittext, ciphersuite, keysize)
                    if re.search('CBC', ciphersuite):
                        target.addsslv3result(poodletext, ciphersuite, keysize)

        #itterate through tls  results, adds finding if any bad suites accepted
        for tls1results in host.getElementsByTagName('tlsv1'):
            for acceptedtls1 in tls1results.getElementsByTagName('acceptedCipherSuites'):
                for suite in acceptedtls1.getElementsByTagName('cipherSuite'):
                    ciphersuite =  suite.getAttributeNode('name').value
                    keysize =  suite.getAttributeNode('keySize').value
                    if re.match(badsuiteregex, ciphersuite):
                        target.addtls1result(badsuitetext, ciphersuite, keysize)
                    if int(keysize) < lowbits:
                        target.addtls1result(lowbittext, ciphersuite, keysize)
        #itterate through tls  results, adds finding if any bad suites accepted
        for tls1_1results in host.getElementsByTagName('tlsv1_1'):
            for acceptedtls1_1 in tls1_1results.getElementsByTagName('acceptedCipherSuites'):
                for suite in acceptedtls1_1.getElementsByTagName('cipherSuite'):
                    ciphersuite =  suite.getAttributeNode('name').value
                    keysize =  suite.getAttributeNode('keySize').value
                    if re.match(badsuiteregex, ciphersuite):
                        target.addtls1_1result(badsuitetext, ciphersuite, keysize)
                    if int(keysize) < lowbits:
                        target.addtls1_1result(lowbittext, ciphersuite, keysize)
        #itterate through tls  results, adds finding if any bad suites accepted
        for tls1_2results in host.getElementsByTagName('tlsv1_2'):
            for acceptedtls1_2 in tls1_2results.getElementsByTagName('acceptedCipherSuites'):
                for suite in acceptedtls1_2.getElementsByTagName('cipherSuite'):
                    ciphersuite =  suite.getAttributeNode('name').value
                    keysize =  suite.getAttributeNode('keySize').value
                    if re.match(badsuiteregex, ciphersuite):
                        target.addtls1_2result(badsuitetext, ciphersuite, keysize)
                    if int(keysize) < lowbits:
                        target.addtls1_2result(lowbittext, ciphersuite, keysize)
        #if were writing to a gluedb, do so, otherwise print to screen.
        if gluedb:
            target.insertfindings()
        else:
            target.printfindings()
'''

    except Exception:
        print "[!E]an error occured :-("
        print Exception
'''