#!/usr/bin/env python
# __author__ = 'adz'
import sys
import re
from classes.results import SslyzeResults
import types
import xml.dom.minidom
from xml.dom.minidom import parse

if __name__ == "__main__":

    results = []
    target = ""
    lowbits = 128
    beastlist = []
    verbose = False
    regex = '^NULL|^EXPORT|^EXP|^DES-CBC-|-DES-CBC-|^RC4'
    exclude = ["Exponent", "timeout", "error", "IOError"]
    scan_result = {}
    dom = parse(sys.argv[1])

    for host in dom.getElementsByTagName('target'):
        expires = ""
        certlistentry = ""
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


        for heartbleedresults in host.getElementsByTagName('heartbleed'):
            try:
                heartbleed = heartbleedresults.getAttributeNode('isVulnerable').value
            except Exception:
                continue


        for sslv2results in host.getElementsByTagName('sslv2'):
            for acceptedsslv2 in sslv2results.getElementsByTagName('acceptedCipherSuites'):
                for suite in acceptedsslv2.getElementsByTagName('cipherSuite'):
                    ciphersuite =  suite.getAttributeNode('name').value
                    keysize =  suite.getAttributeNode('keySize').value
                    target.addsslv2result('SSL version 2 accepted', ciphersuite, keysize)
                    if re.match(regex, ciphersuite):
                        target.addsslv2result('Bad Suite Found', ciphersuite, keysize)
                    if int(keysize) < lowbits:
                        target.addsslv2result('Low Key Size', ciphersuite, keysize)


        target = SslyzeResults(ip, port, heartbleed, addressvalue=addressvalue,
                               certlistentry=certlistentry, expires=expires)

        for sslv2results in host.getElementsByTagName('sslv2'):
            for acceptedsslv2 in sslv2results.getElementsByTagName('acceptedCipherSuites'):
                for suite in acceptedsslv2.getElementsByTagName('cipherSuite'):
                    ciphersuite =  suite.getAttributeNode('name').value
                    keysize =  suite.getAttributeNode('keySize').value
                    target.addsslv2result('SSL version 2 accepted', ciphersuite, keysize)
                    if re.match(regex, ciphersuite):
                        target.addsslv2result('Bad Suite Found', ciphersuite, keysize)
                    if int(keysize) < lowbits:
                        target.addsslv2result('Low Key Size', ciphersuite, keysize)

        for sslv3results in host.getElementsByTagName('sslv3'):
            for acceptedsslv3 in sslv3results.getElementsByTagName('acceptedCipherSuites'):
                for suite in acceptedsslv3.getElementsByTagName('cipherSuite'):
                    ciphersuite =  suite.getAttributeNode('name').value
                    keysize =  suite.getAttributeNode('keySize').value
                    if re.match(regex, ciphersuite):
                        target.addsslv3result('Bad Suite Found', ciphersuite, keysize)
                    if int(keysize) < lowbits:
                        target.addsslv3result('Low Key Size', ciphersuite, keysize)


        for tls1results in host.getElementsByTagName('tlsv1'):
            for acceptedtls1 in tls1results.getElementsByTagName('acceptedCipherSuites'):
                for suite in acceptedtls1.getElementsByTagName('cipherSuite'):
                    ciphersuite =  suite.getAttributeNode('name').value
                    keysize =  suite.getAttributeNode('keySize').value
                    if re.match(regex, ciphersuite):
                        target.addtls1result('Bad Suite Found', ciphersuite, keysize)
                    if int(keysize) < lowbits:
                        target.addtls1result('Low Key Size', ciphersuite, keysize)

        for tls1_1results in host.getElementsByTagName('tlsv1_1'):
            for acceptedtls1_1 in tls1_1results.getElementsByTagName('acceptedCipherSuites'):
                for suite in acceptedtls1_1.getElementsByTagName('cipherSuite'):
                    ciphersuite =  suite.getAttributeNode('name').value
                    keysize =  suite.getAttributeNode('keySize').value
                    if re.match(regex, ciphersuite):
                        target.addtls1_1result('Bad Suite Found', ciphersuite, keysize)
                    if int(keysize) < lowbits:
                        target.addtls1_1result('Low Key Size', ciphersuite, keysize)

        for tls1_2results in host.getElementsByTagName('tlsv1_2'):
            for acceptedtls1_2 in tls1_2results.getElementsByTagName('acceptedCipherSuites'):
                for suite in acceptedtls1_2.getElementsByTagName('cipherSuite'):
                    ciphersuite =  suite.getAttributeNode('name').value
                    keysize =  suite.getAttributeNode('keySize').value
                    if re.match(regex, ciphersuite):
                        target.addtls1_2result('Bad Suite Found', ciphersuite, keysize)
                    if int(keysize) < lowbits:
                        target.addtls1_2result('Low Key Size', ciphersuite, keysize)


        target.printfindings()
'''

    except Exception:
        print "[!E]an error occured :-("
        print Exception
'''