#!/usr/bin/python
# -*- coding: iso-8859-15 -*-
"""
$Id$

This file is part of the xsser project, http://xsser.sourceforge.net.

Copyright (c) 2011/2012/2013 psy <root@lordepsylon.net> - <epsylon@riseup.net>

xsser is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation version 3 of the License.

xsser is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along
with xsser; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""
import json
import datetime

class json_reporting(object):
    """
    Print results from an attack in an JSON fashion
    """
    def __init__(self, xsser):
        # initialize main XSSer
        self.instance = xsser

	# some counters
        self.xsr_founded = 0
        self.xsa_founded = 0
        self.coo_founded = 0
        self.dcp_founded = 0
        self.dom_founded = 0
        self.ind_founded = 0

    def print_json_results(self, filename):
		root = {}
		root["report"] = root
		hdr = {}
		title = {}
		title["title"] = "XSSer Security Report: " + str(datetime.datetime.now())
		hdr["header"] = title
		root["report"] = hdr
		abstract = {}
		total_injections = len(self.instance.hash_found) + len(self.instance.hash_notfound)
		
		if len(self.instance.hash_found) + len(self.instance.hash_notfound) == 0:
			pass 

		total_inj_i = len(self.instance.hash_found) + len(self.instance.hash_notfound)
	
		try: 
			accur_inj = "%s %%" % (str((len(self.instance.hash_found) * 100) / total_inj_i), )
		except ZeroDivisionError:
			accur_inj = "0 %"
			
		injections = {"total" : str(total_inj_i), "failed" : str(len(self.instance.hash_notfound)),
				      "successful" : str(len(self.instance.hash_found)), "accur" : accur_inj}
					  
		abstract["injections"] = injections
		root["abstract"] = abstract
		
		
		if self.instance.options.statistics:
			stats = {}
			test_time = datetime.datetime.now() - self.instance.time
			stats["duracion"] = str(test_time)
			total_connections = self.instance.success_connection + self.instance.not_connection + self.instance.forwarded_connection + self.instance.other_connection
			tcon_text = str(total_connections)
			okcon_text = str(self.instance.success_connection)
			notfound_text = str(self.instance.not_connection)
			forbidden_text = str(self.instance.forwarded_connection)
			othercon_text = str(self.instance.other_connection)
			try:
				st_accur.text = "%s %%" % (str(((len(str((self.instance.success_connection) * 100))) / total_connections)), )
			except ZeroDivisionError:
				st_accur.text = "0 %"

			stats["connections"] = {"total" : tcon_text, "ok" : okcon_text, "not found" : notfound_text,
									"forbidden" : forbiddem_text, "other" : othercon_text, "accur" : st_accur_text}

			st_inj_total_text = str(total_injections)
			st_success_text = str(len(self.instance.hash_found))
			st_failed_text = str(len(self.instance.hash_notfound))

			try:
				st_accur_text = "%s %%" % (str(((len(self.instance.hash_found) * 100) / total_injections)),)
			except ZeroDivisionError:
				st_accur_text = "0 %"

			stats["injections"] = {"total" : st_inj_total_text, "successful" : st_success_text, "failed" : st_failed_text,
								   "accur" : st_accur_text}

			root["stats"] = stats

		results = {}
		for line in self.instance.hash_found:
			attack = {}
			url_text = line[0]
			attack["injection"] = url_text
			attack_url = self.instance.apply_postprocessing(line[0], line[1], line[2], line[3], line[4], line[5], line[6])
			if self.instance.options.onm or self.instance.options.ifr or self.instance.options.b64  or self.instance.options.dos or self.instance.options.doss or self.instance.options.finalremote or self.instance.options.finalpayload:
				attack["finalattack"] = ""
			else:
				attack["finalattack"] = None
			if line[2] == "xsr":
				self.xsr_founded = self.xsr_founded +1
				xsr_vulnerable_host = [{"payload":str(line[4]), "target":str(line[6])}]
				if xsr_vulnerable_host[0]["payload"] == line[4] and xsr_vulnerable_host[0]["target"] == line[6] and self.xsr_founded > 1:
					pass
				else:
					aurl_text = "Cross Site Referer Scripting!! " + str(line[6]) + "/"+str(line[4])
					attack["finalattack"] = aurl_text
			elif line[2] == "xsa":
				self.xsa_founded = self.xsa_founded +1
				xsa_vulnerable_host = [{"payload":str(line[4]), "target":str(line[6])}]
				if xsa_vulnerable_host[0]["payload"] == line[4] and xsa_vulnerable_host[0]["target"] == line[6] and self.xsa_founded > 1:
					pass
				else:
					aurl_text = "Cross Site Agent Scripting!! " + str(line[6]) + "/"+str(line[4])
					attack["finalattack"] = aurl_text
			elif line[2] == "coo":
				self.coo_founded = self.coo_founded +1
				coo_vulnerable_host = [{"payload":str(line[4]), "target":str(line[6])}]
				if coo_vulnerable_host[0]["payload"] == line[4] and coo_vulnerable_host[0]["target"] == line[6] and self.coo_founded > 1:
					pass
				else:
					aurl_text = "Cross Site Cookie Scripting!! " + str(line[6]) + "/"+str(line[4])
					attack["finalattack"] = aurl_text
			elif line[2] == "dcp":
				self.dcp_founded = self.dcp_founded +1
				dcp_vulnerable_host = [{"payload":str(line[4]), "target":str(line[6])}]
				if dcp_vulnerable_host[0]["payload"] == line[4] and dcp_vulnerable_host[0]["target"] == line[6] and self.dcp_founded > 1:
					pass
				else:
					aurl_text = "Data Control Protocol injections!! " + str(line[6]) + "/"+str(line[4])
					attack["finalattack"] = aurl_text
			elif line[2] == "dom":
				self.dom_founded = self.dom_founded +1
				dom_vulnerable_host = [{"payload":str(line[4]), "target":str(line[6])}]
				if dom_vulnerable_host[0]["payload"] == line[4] and dom_vulnerable_host[0]["target"] == line[6] and self.dom_founded > 1:
					pass
				else:
					aurl_text = "Document Object Model injections!! " + str(line[6]) + "/"+str(line[4])
					attack["finalattack"] = aurl_text
			elif line[2] == "ind":
				self.ind_founded = self.ind_founded +1
				ind_vulnerable_host = [{"payload":str(line[4]), "target":str(line[6])}]
				if ind_vulnerable_host[0]["payload"] == line[4] and ind_vulnerable_host[0]["target"] == line[6] and self.ind_founded > 1:
					pass
				else:
					aurl_text = "HTTP Response Splitting Induced code!! " + str(line[6]) + "/"+str(line[4])
					attack["finalattack"] = aurl_text
			else:
				if attack["finalattack"] == None:
					pass
				else:
					aurl_text = attack_url
					attack["finalattack"] = aurl_text

			results["attack"] = attack
			
			if line[2] not in ["xsr", "xsa", "coo", "dcp", "dom", "ind"]:
				browsers_text = line[1]
				results["browser"] = browsers_text
				method_text = line[2]
				results["method"] = method_text

		if not self.instance.hash_found:
			msg_text = "Failed injection(s): " +str(''.join([u[0] for u in self.instance.hash_notfound])) 
			results["msg"] = msg_text

		root["results"] = results
		f = open(filename, 'w')
		f.write(json.dumps(root))
		f.close()

