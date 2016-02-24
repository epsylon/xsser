#!/usr/bin/env python
# -*- coding: utf-8 -*-"
# vim: set expandtab tabstop=4 shiftwidth=4:
"""
$Id$

This file is part of the xsser project, http://xsser.03c8.net

Copyright (c) 2011/2016 psy <epsylon@riseup.net>

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
import xml.etree.ElementTree as ET
import datetime

class xml_reporting(object):
    """
    Print results from an attack in an XML fashion
    """
    def __init__(self, xsser):
        # initialize main XSSer
        self.instance = xsser

	# some counters
        self.xsr_found = 0
        self.xsa_found = 0
        self.coo_found = 0
        self.dcp_found = 0
        self.dom_found = 0
        self.ind_found = 0

    def print_xml_results(self, filename):
        root = ET.Element("report")
        hdr = ET.SubElement(root, "header")
        title = ET.SubElement(hdr, "title")
        title.text = "XSSer Security Report: " + str(datetime.datetime.now())
        abstract = ET.SubElement(root, "abstract")
        total_injections = len(self.instance.hash_found) + len(self.instance.hash_notfound)

        if len(self.instance.hash_found) + len(self.instance.hash_notfound) == 0:
            pass 
        injections = ET.SubElement(abstract, "injections")
        total_inj = ET.SubElement(injections, "total")
        failed_inj = ET.SubElement(injections, "failed")
        success_inj = ET.SubElement(injections, "successful")
        accur_inj = ET.SubElement(injections, "accur")

        total_inj_i = len(self.instance.hash_found) + len(self.instance.hash_notfound)

        total_inj.text = str(total_inj_i)
        failed_inj.text = str(len(self.instance.hash_notfound))
        success_inj.text = str(len(self.instance.hash_found))
        try: 
            accur_inj.text = "%s %%" % (str((len(self.instance.hash_found) * 100) / total_inj_i), )
        except ZeroDivisionError:
            accur_inj.text = "0 %"

        if self.instance.options.statistics:
            stats = ET.SubElement(root, "stats")
            test_time = datetime.datetime.now() - self.instance.time
            time_ = ET.SubElement(stats, "duration")
            time_.text = str(test_time)
            total_connections = self.instance.success_connection + self.instance.not_connection + self.instance.forwarded_connection + self.instance.other_connection
            con = ET.SubElement(stats, "connections")
            tcon = ET.SubElement(con, "total")
            tcon.text = str(total_connections)
            okcon = ET.SubElement(con, "ok")
            okcon.text = str(self.instance.success_connection)
            notfound = ET.SubElement(con, "notfound")
            notfound.text = str(self.instance.not_connection)
            forbidden = ET.SubElement(con, "forbidden")
            forbidden.text = str(self.instance.forwarded_connection)
            othercon = ET.SubElement(con, "other")
            othercon.text = str(self.instance.other_connection)
            st_accur = ET.SubElement(con, "accur")
            try:
                st_accur.text = "%s %%" % (str(((len(self.instance.success_connection) * 100) / total_connections)), )
            except ZeroDivisionError:
                st_accur.text = "0 %"
            st_inj = ET.SubElement(stats, "injections")
            st_inj_total = ET.SubElement(st_inj, "total")
            st_inj_total.text = str(total_injections)
            st_success = ET.SubElement(st_inj, "successful")
            st_success.text = str(len(self.instance.hash_found))
            st_failed = ET.SubElement(st_inj, "failed")
            st_failed.text = str(len(self.instance.hash_notfound))
            st_accur = ET.SubElement(st_inj, "accur")
            try:
                st_accur.text = "%s %%" % (str(((len(self.instance.hash_found) * 100) / total_injections)),)
            except ZeroDivisionError:
                st_accur.text = "0 %"
        results = ET.SubElement(root, "results")
        for line in self.instance.hash_found:
            attack = ET.SubElement(results, "attack")
            url_ = ET.SubElement(attack, "injection")
            url_.text = line[0]
            attack_url = self.instance.apply_postprocessing(line[0], line[1], line[2], line[3], line[4], line[5], line[6])
            if self.instance.options.onm or self.instance.options.ifr or self.instance.options.b64  or self.instance.options.dos or self.instance.options.doss or self.instance.options.finalremote or self.instance.options.finalpayload:
                aurl = ET.SubElement(attack, "finalattack")
            else:
                aurl = None
            if line[2] == "xsr":
                self.xsr_found = self.xsr_found +1
                xsr_vulnerable_host = [{"payload":str(line[4]), "target":str(line[6])}]
                if xsr_vulnerable_host[0]["payload"] == line[4] and xsr_vulnerable_host[0]["target"] == line[6] and self.xsr_found > 1:
                    pass
                else:
                    aurl.text = "Cross Site Referer Scripting!! " + str(line[6]) + "/"+str(line[4])
            elif line[2] == "xsa":
                self.xsa_found = self.xsa_found +1
                xsa_vulnerable_host = [{"payload":str(line[4]), "target":str(line[6])}]
                if xsa_vulnerable_host[0]["payload"] == line[4] and xsa_vulnerable_host[0]["target"] == line[6] and self.xsa_found > 1:
                    pass
                else:
                    aurl.text = "Cross Site Agent Scripting!! " + str(line[6]) + "/"+str(line[4])
            elif line[2] == "coo":
                self.coo_found = self.coo_found +1
                coo_vulnerable_host = [{"payload":str(line[4]), "target":str(line[6])}]
                if coo_vulnerable_host[0]["payload"] == line[4] and coo_vulnerable_host[0]["target"] == line[6] and self.coo_found > 1:
                    pass
                else:
                    aurl.text = "Cross Site Cookie Scripting!! " + str(line[6]) + "/"+str(line[4])
            elif line[2] == "dcp":
                self.dcp_found = self.dcp_found +1
                dcp_vulnerable_host = [{"payload":str(line[4]), "target":str(line[6])}]
                if dcp_vulnerable_host[0]["payload"] == line[4] and dcp_vulnerable_host[0]["target"] == line[6] and self.dcp_found > 1:
                    pass
                else:
                    aurl.text = "Data Control Protocol injections!! " + str(line[6]) + "/"+str(line[4])
            elif line[2] == "dom":
                self.dom_found = self.dom_found +1
                dom_vulnerable_host = [{"payload":str(line[4]), "target":str(line[6])}]
                if dom_vulnerable_host[0]["payload"] == line[4] and dom_vulnerable_host[0]["target"] == line[6] and self.dom_found > 1:
                    pass
                else:
                    aurl.text = "Document Object Model injections!! " + str(line[6]) + "/"+str(line[4])
            elif line[2] == "ind":
                self.ind_found = self.ind_found +1
                ind_vulnerable_host = [{"payload":str(line[4]), "target":str(line[6])}]
                if ind_vulnerable_host[0]["payload"] == line[4] and ind_vulnerable_host[0]["target"] == line[6] and self.ind_found > 1:
                    pass
                else:
                    aurl.text = "HTTP Response Splitting Induced code!! " + str(line[6]) + "/"+str(line[4])
            else:
                if aurl == None:
                    pass
                else:
                    aurl.text = attack_url
            if line[2] == "xsr" or line[2] == "xsa" or line[2] == "coo" or line[2] == "dcp" or line[2] == "dom" or line[2] == "ind":
                pass
            else:
                browsers = ET.SubElement(attack, "browsers")
                browsers.text = line[1]
                method = ET.SubElement(attack, "method")
                method.text = line[2]

        if not self.instance.hash_found:
            msg = ET.SubElement(results, "message")
            msg.text = "Failed injection(s): " +str(''.join([u[0] for u in self.instance.hash_notfound])) 
        tree = ET.ElementTree(root)
        tree.write(filename)

