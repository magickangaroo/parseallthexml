#!/usr/bin/env python3
# __author__ = 'adz'
#pulls out ssl tunnels. in format for the sslscanner
# -*- coding: utf-8 -*-
import re
from classes.nmapresults import nmapResults
import ConfigParser
import argparse
import os
import logging
from common.common import loggingobject
"""
Had to modify nmap.py (version 3)

added :
                '''ajh adding'''
                name,product,version,extrainfo,conf,cpe,tunnel = '','','','','','',''
                '''ajh adding'''
                for dname in dport.getElementsByTagName('service'):
                    name = dname.getAttributeNode('name').value
                    if dname.hasAttribute('product'):
                        product = dname.getAttributeNode('product').value
                    '''ajh adding'''
                    if dname.hasAttribute('tunnel'):
                        tunnel = dname.getAttributeNode('tunnel').value
                    '''ajh adding'''


                    scan_result['scan'][host][proto][port] = {'state': state,
                                  'reason': reason,
                                  'name': name,
                                  'product': product,
                                  'tunnel': tunnel,

                                  should suggest this up to maintainer at some point.

"""



import nmap
import sys

def getguids(config):
    #grab the guid section, convert from list of tuples to a dictionary

    guids = dict(config.items('guids'))
    return guids

def gettester(config):
    value = config.get('testinginfo', 'tester')
    return value

#these could be furhter optimised, but am leaving as is for readablility (eg all tcp checks in one)

def dontpcheck(nm):

    try:
        for port in nm[host]['udp']:
            try:

                target = nmapResults(host, port, guids, tester, gluedb=gluedb)
                '''product =  nm[host]['udp'][port]['product']
                print (product)
                '''
                if port == 123 and nm[host]['udp'][port]['state'] == 'open':
                    excerpt = []
                    ntpmonlistresults = (nm[host]['udp'][port]['script']['ntp-monlist'])
                    #two findings, if not many clients as it indictes its not the intended role of the server
                    nmapscriptresults =  ntpmonlistresults
                    splitnmapscriptresults = nmapscriptresults.split('\n')
                    try:
                        privateclientsresult = int(re.search('Private Clients \((.*)\)', ntpmonlistresults).group(1))
                    except:
                        privateclientsresult = 0
                    try:
                        publicclientsresult = int(re.search('Public Clients \((.*)\)', ntpmonlistresults).group(1))
                    except:
                        publicclientsresult = 0

                    totalclients =  privateclientsresult + publicclientsresult
                    if totalclients <= clientthreashold:

                        for line in splitnmapscriptresults:
                            if "Clients" in line:
                                excerpt.append(line)

                            target.adduneccessaryfinding("Uneccessary service found", 'ntp', excerpt,
                                                     numberofclients=totalclients)

                    linecount = int(len(splitnmapscriptresults)*0.2)
                    excerpt = splitnmapscriptresults
                    target.addntpmonlist(excerpt)
                    target.insertfindings()

            except KeyError:
                pass

    except KeyError:
            pass

def dohttpmethodcheck(nm):

    try:
        for port in nm[host]['tcp']:
            try:

                target = nmapResults(host, port, guids, tester, gluedb=gluedb)

                if nm[host]['tcp'][port]['state'] == 'open':
                    excerpt = []

                    if "Potentially risky methods" in nm[host]['tcp'][port]['script']['http-methods']:
                        excerpt = nm[host]['tcp'][port]['script']['http-methods']
                        riskymethods = excerpt.split('Potentially risky methods:')[1]

                        target.adduneccessaryhttpfinding("Uneccessary HTTP Method Found", "http", excerpt,
                                                    riskymethods=riskymethods)

                        target.insertfindings()


            except KeyError:
                pass

    except KeyError:
            pass

def dordpciphersuite(nm):
    try:
        for port in nm[host]['tcp']:


            try:
                if nm[host]['tcp'][port]['name'] == "ms-wbt-server" and nm[host]['tcp'][port]['state'] == 'open':

                    target = nmapResults(host, port, guids, tester, gluedb=gluedb)
                    excerpt = nm[host]['tcp'][port]['script']['rdp-enum-encryption']
                    if "RC4"  in excerpt or "Client Compatible" in excerpt:
                        target.addweakrdpfinding("Weak RDP cipher supported", "rdp", excerpt)

                    #print target.weakrdpfinding
                    target.insertfindings()

            except KeyError:
                pass

    except KeyError:
            pass

def dosshciphersuite(nm):
    try:
        for port in nm[host]['tcp']:


            try:
                if nm[host]['tcp'][port]['name'] == "ssh" and nm[host]['tcp'][port]['state'] == 'open':

                    target = nmapResults(host, port, guids, tester, gluedb=gluedb)
                    excerpt = nm[host]['tcp'][port]['script']['ssh2-enum-algos']


                    if "cbc" in excerpt.lower():
                        target.addweaksshfinding("Weak SSH cipher supported", "rdp", excerpt)

                    listofbadhmacs = ["hmac-md5", "hmac-sha1-96"]

                    if any(mac in excerpt.lower() for mac in listofbadhmacs):
                        target.addweaksshfinding("Weak SSH HMAC supported", "rdp", excerpt)

                    target.insertfindings()
                    
            except KeyError:
                pass

    except KeyError:
            pass

if __name__ == '__main__':

    #specific vars
    clientthreashold = 2

    parser = argparse.ArgumentParser(description='This is a parser for sslyze')
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

    if args.gdb:
        gluedb = args.gdb
    else:
        gluedb = False

    #Get info out of config
    guids = getguids(config)
    tester = gettester(config)


    #open supplied file for parsing, read in as a string rather than list
    with open(args.xml, 'r') as f:
        data = f.read().replace('\n', '')

    nm = nmap.PortScanner()

    #nm.analyse_nmap_xml_scan(nmap_xml_output=bytes.decode(data))
    nm.analyse_nmap_xml_scan(data)

    for host in nm.all_hosts():
        dontpcheck(nm)
        dohttpmethodcheck(nm)
        dordpciphersuite(nm)
        dosshciphersuite(nm)


