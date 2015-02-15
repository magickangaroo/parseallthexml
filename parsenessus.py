__author__ = 'adz'

#!/usr/bin/env python
# __author__ = 'adz'
import sys
import re
from classes.nessusresults import NessusResults
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='This is a parser for sslyze')
    results = []
    host = ""
    verbose = False


    parser.add_argument('--xml', '-x', help="Wheres the xml at?", required=True)
    parser.add_argument('--gdb', '-g', help="Wheres the glue at?", required=False)
    parser.add_argument('--cfg', '-c', help="any config file?", required=True)
    parser.add_argument('--log', '-l', help="any log file? defaults to logs/ssylzerxml.log",
                        required=False, default='logs/sslyzerxml.log')
    args = parser.parse_args()
    #logging to file and screen

    loggingobject(args, logging)
    logging.info('This takes ages to run due to size of the nessus xml, be patient.')

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
    logging.info('Should start seeing things now the dom is parsed')

    for reporthost in dom.getElementsByTagName('ReportHost'):
        host = reporthost.getAttributeNode('name').value

        for report in reporthost.getElementsByTagName('ReportItem'):
            pluginname = report.getAttributeNode('pluginName').value
            if pluginname == "SSL Self-Signed Certificate":
                port = report.getAttributeNode('port').value
                if port == '3389':
                    logging.info('Not logging this as its RDP, and should be logged under '
                                 'Terminal Services (RDP) Data Vulnerable to Interception')
                else:

                    excerpt = report.getElementsByTagName('plugin_output')[0].firstChild.nodeValue
                    #print dir(output)
                    target = NessusResults(host, port, guids, tester, logging,  gluedb=gluedb)

                    target.addselfsignedcertfinding(pluginname, "TCP", excerpt)
                    target.insertfindings()