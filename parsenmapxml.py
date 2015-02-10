#!/usr/bin/env python3
# __author__ = 'adz'
#pulls out ssl tunnels. in format for the sslscanner
# -*- coding: utf-8 -*-

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
if __name__ == '__main__':

    #open supplied file for parsing, read in as a string rather than list
    with open(sys.argv[1], 'r') as f:
        data = f.read().replace('\n', '')

    nm = nmap.PortScanner()

    #nm.analyse_nmap_xml_scan(nmap_xml_output=bytes.decode(data))
    nm.analyse_nmap_xml_scan(data)

    for host in nm.all_hosts():
        print('----------------------------------------------------')
        print('Host : %s (%s)' % (host, nm[host].hostname()))

        try:
            for port in nm[host]['tcp']:
                try:

                    product =  nm[host]['tcp'][port]['product']
                    print (nm[host]['tcp'][port]['tunnel'])
                    if nm[host]['tcp'][port]['tunnel'] == "ssl":
                        print ("hi")
                        print('%s,%s,%i,no-https' % (host, nm[host].hostname(), port))
                        print('[i]SSLlyze %s:%s #%s' % (host, port, product))
                except KeyError:
                    pass
        except KeyError:
                pass