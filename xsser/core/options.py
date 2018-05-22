#!/usr/bin/env python
# -*- coding: utf-8 -*-"
# vim: set expandtab tabstop=4 shiftwidth=4:
"""
$Id$

This file is part of the xsser project, https://xsser.03c8.net

Copyright (c) 2011/2018 psy <epsylon@riseup.net>

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
import optparse
import core.fuzzing.vectors
import core.fuzzing.DCP
import core.fuzzing.DOM
import core.fuzzing.HTTPsr

class XSSerOptions(optparse.OptionParser):
    def __init__(self, *args):
        optparse.OptionParser.__init__(self, 
                           description='Cross Site "Scripter" is an automatic -framework- to detect, exploit and\nreport XSS vulnerabilities in web-based applications.',
                           prog='XSSer.py',
			   version='\nXSSer v1.7b: "ZiKA-47 Swarm!" - 2011/2018 - (GPLv3.0) -> by psy\n',
                           usage= '\n\nxsser [OPTIONS] [--all <url> |-u <url> |-i <file> |-d <dork> (options)|-l ] [-g <get> |-p <post> |-c <crawl> (options)]\n[Request(s)] [Checker(s)] [Vector(s)] [Anti-antiXSS/IDS] [Bypasser(s)] [Technique(s)] [Final Injection(s)] [Reporting] {Miscellaneous}')
        self.set_defaults(verbose=False, threads=5, retries=1, delay=0, timeout=30,
                          silent=False)
        self.disable_interspersed_args()
        self.vectors_fuzz = len(core.fuzzing.vectors.vectors)
        self.vectors_dcp = len(core.fuzzing.DCP.DCPvectors)
        self.vectors_dom = len(core.fuzzing.DOM.DOMvectors)
        self.vectors_httpsr = len(core.fuzzing.HTTPsr.HTTPrs_vectors)
        self.total_vectors = str(self.vectors_fuzz+self.vectors_dcp+self.vectors_dom+self.vectors_httpsr)

        self.add_option("-s", "--statistics",  action="store_true", dest="statistics", help="show advanced statistics output results")
        self.add_option("-v", "--verbose", action="store_true", dest="verbose", help="active verbose mode output results")
        self.add_option("--gtk", action="store_true", dest="xsser_gtk", help="launch XSSer GTK Interface")
        #self.add_option("--swarm", action="store_true", dest="xsser_web", help="launch XSSer Swarm daemon(s) + Web-Shell")
        self.add_option("--wizard", action="store_true", dest="wizard", help="start Wizard Helper!")

        group1 = optparse.OptionGroup(self, "*Special Features*",
        "You can set Vector(s) and Bypasser(s) to build complex scripts for XSS code embedded. XST allows you to discover if target is vulnerable to 'Cross Site Tracing' [CAPEC-107]:")
        group1.add_option("--imx", action="store", dest="imx", help="IMX - Create an image with XSS (--imx image.png)")
        group1.add_option("--fla", action="store", dest="flash", help="FLA - Create a flash movie with XSS (--fla movie.swf)")
        group1.add_option("--xst", action="store", dest="xst", help="XST - Cross Site Tracing (--xst http(s)://host.com)")
        self.add_option_group(group1)

        group2 = optparse.OptionGroup(self, "*Select Target(s)*",
        "At least one of these options must to be specified to set the source to get target(s) urls from:")
        group2.add_option("--all", action="store", dest="target", help="Automatically audit an entire target")
        group2.add_option("-u", "--url", action="store", dest="url", help="Enter target to audit") 
        group2.add_option("-i", action="store", dest="readfile", help="Read target(s) urls from file")
        group2.add_option("-d", action="store", dest="dork", help="Search target(s) using a query (ex: 'news.php?id=')")
        group2.add_option("-l", action="store_true", dest="dork_file", help="Search from a list of 'dorks'")
        group2.add_option("--De", action="store", dest="dork_engine", help="Use this search engine (default: yahoo)")
        group2.add_option("--Da", action="store_true", dest="dork_mass", help="Search massively using all search engines")
        self.add_option_group(group2)

        group3 = optparse.OptionGroup(self, "*Select type of HTTP/HTTPS Connection(s)*",
        "These options can be used to specify which parameter(s) we want to use as payload(s). Set 'XSS' as keyword on the place(s) that you want to inject:")
        group3.add_option("-g", action="store", dest="getdata", help="Send payload using GET (ex: '/menu.php?id=3&q=XSS')")
        group3.add_option("-p", action="store", dest="postdata", help="Send payload using POST (ex: 'foo=1&bar=XSS')")
        group3.add_option("-c", action="store", dest="crawling", help="Number of urls to crawl on target(s): 1-99999")
        group3.add_option("--Cw", action="store", dest="crawler_width", help="Deeping level of crawler: 1-5 (default 3)")
        group3.add_option("--Cl", action="store_true", dest="crawler_local", help="Crawl only local target(s) urls (default TRUE)") 
        self.add_option_group(group3)

        group4 = optparse.OptionGroup(self, "*Configure Request(s)*",
        "These options can be used to specify how to connect to the target(s) payload(s). You can choose multiple:") 
        group4.add_option("--cookie", action="store", dest="cookie", help="Change your HTTP Cookie header")
        group4.add_option("--drop-cookie", action="store_true", dest="dropcookie", help="Ignore Set-Cookie header from response")
        group4.add_option("--user-agent", action="store", dest="agent", help="Change your HTTP User-Agent header (default SPOOFED)")
        group4.add_option("--referer", action="store", dest="referer", help="Use another HTTP Referer header (default NONE)")
        group4.add_option("--xforw", action="store_true", dest="xforw", help="Set your HTTP X-Forwarded-For with random IP values")
        group4.add_option("--xclient", action="store_true", dest="xclient", help="Set your HTTP X-Client-IP with random IP values")
        group4.add_option("--headers", action="store", dest="headers", help="Extra HTTP headers newline separated")
        group4.add_option("--auth-type", action="store", dest="atype", help="HTTP Authentication type (Basic, Digest, GSS or NTLM)") 
        group4.add_option("--auth-cred", action="store", dest="acred", help="HTTP Authentication credentials (name:password)")
        #group4.add_option("--auth-cert", action="store", dest="acert", help="HTTP Authentication certificate (key_file,cert_file)") 
        group4.add_option("--proxy", action="store", dest="proxy", help="Use proxy server (tor: http://localhost:8118)")
        group4.add_option("--ignore-proxy", action="store_true", dest="ignoreproxy", help="Ignore system default HTTP proxy")
        group4.add_option("--timeout", action="store", dest="timeout", type="int", help="Select your timeout (default 30)")
        group4.add_option("--retries", action="store", dest="retries", type="int", help="Retries when the connection timeouts (default 1)")
        group4.add_option("--threads", action="store", dest="threads", type="int", help="Maximum number of concurrent HTTP requests (default 5)") 
        group4.add_option("--delay", action="store", dest="delay", type="int", help="Delay in seconds between each HTTP request (default 0)")
        group4.add_option("--tcp-nodelay", action="store_true", dest="tcp_nodelay", help="Use the TCP_NODELAY option")
        group4.add_option("--follow-redirects", action="store_true", dest="followred", help="Follow server redirection responses (302)")
        group4.add_option("--follow-limit", action="store", dest="fli", type="int", help="Set limit for redirection requests (default 50)")
        self.add_option_group(group4)

        group5 = optparse.OptionGroup(self, "*Checker Systems*",
        "These options are useful to know if your target is using filters against XSS attacks:")
        group5.add_option("--hash", action="store_true", dest="hash", help="send a hash to check if target is repeating content")
        group5.add_option("--heuristic", action="store_true", dest="heuristic", help="discover parameters filtered by using heuristics")
        group5.add_option("--discode", action="store", dest="discode", help="set code on reply to discard an injection")
        group5.add_option("--checkaturl", action="store", dest="alt", help="check reply using: alternative url -> Blind XSS")
        group5.add_option("--checkmethod", action="store", dest="altm", help="check reply using: GET or POST (default: GET)")
        group5.add_option("--checkatdata", action="store", dest="ald", help="check reply using: alternative payload") 
        group5.add_option("--reverse-check", action="store_true", dest="reversecheck", help="establish a reverse connection from target to XSSer to certify that is 100% vulnerable (recommended!)")
        self.add_option_group(group5)

        group6 = optparse.OptionGroup(self, "*Select Vector(s)*",
        "These options can be used to specify injection(s) code. Important if you don't want to inject a common XSS vector used by default. Choose only one option:")
        group6.add_option("--payload", action="store", dest="script", help="OWN  - Inject your own code")
        group6.add_option("--auto", action="store_true", dest="fuzz", help="AUTO - Inject a list of vectors provided by XSSer")
        self.add_option_group(group6)

        group13 = optparse.OptionGroup(self, "*Anti-antiXSS Firewall rules*",
        "These options can be used to try to bypass specific WAF/IDS products. Choose only if required:")
        group13.add_option("--Phpids0.6.5", action="store_true", dest="phpids065", help="PHPIDS (0.6.5) [ALL]")
        group13.add_option("--Phpids0.7", action="store_true", dest="phpids070", help="PHPIDS (0.7) [ALL]")
        group13.add_option("--Imperva", action="store_true", dest="imperva", help="Imperva Incapsula [ALL]")
        group13.add_option("--Webknight", action="store_true", dest="webknight", help="WebKnight (4.1) [Chrome]")
        group13.add_option("--F5bigip", action="store_true", dest="f5bigip", help="F5 Big IP [Chrome + FF + Opera]")
        group13.add_option("--Barracuda", action="store_true", dest="barracuda", help="Barracuda WAF [ALL]")
        group13.add_option("--Modsec", action="store_true", dest="modsec", help="Mod-Security [ALL]")
        group13.add_option("--Quickdefense", action="store_true", dest="quickdefense", help="QuickDefense [Chrome]")
        self.add_option_group(group13)
       
        group7 = optparse.OptionGroup(self, "*Select Bypasser(s)*",
        "These options can be used to encode vector(s) and try to bypass possible anti-XSS filters. They can be combined with other techniques:")
        group7.add_option("--Str", action="store_true", dest="Str", help="Use method String.FromCharCode()")
        group7.add_option("--Une", action="store_true", dest="Une", help="Use Unescape() function")
        group7.add_option("--Mix", action="store_true", dest="Mix", help="Mix String.FromCharCode() and Unescape()")
        group7.add_option("--Dec", action="store_true", dest="Dec", help="Use Decimal encoding")
        group7.add_option("--Hex", action="store_true", dest="Hex", help="Use Hexadecimal encoding")
        group7.add_option("--Hes", action="store_true", dest="Hes", help="Use Hexadecimal encoding with semicolons")
        group7.add_option("--Dwo", action="store_true", dest="Dwo", help="Encode IP addresses with DWORD")
        group7.add_option("--Doo", action="store_true", dest="Doo", help="Encode IP addresses with Octal")
        group7.add_option("--Cem", action="store", dest="Cem", help="Set different 'Character Encoding Mutations' (reversing obfuscators) (ex: 'Mix,Une,Str,Hex')")
        self.add_option_group(group7)

        group8 = optparse.OptionGroup(self, "*Special Technique(s)*",
        "These options can be used to inject code using different XSS techniques. You can choose multiple:")
        group8.add_option("--Coo", action="store_true", dest="coo", help="COO - Cross Site Scripting Cookie injection")
        group8.add_option("--Xsa", action="store_true", dest="xsa", help="XSA - Cross Site Agent Scripting")
        group8.add_option("--Xsr", action="store_true", dest="xsr", help="XSR - Cross Site Referer Scripting")
        group8.add_option("--Dcp", action="store_true", dest="dcp", help="DCP - Data Control Protocol injections")
        group8.add_option("--Dom", action="store_true", dest="dom", help="DOM - Document Object Model injections")
        group8.add_option("--Ind", action="store_true", dest="inducedcode", help="IND - HTTP Response Splitting Induced code")
        group8.add_option("--Anchor", action="store_true", dest="anchor", help="ANC - Use Anchor Stealth payloader (DOM shadows!)")
        self.add_option_group(group8)

        group9 = optparse.OptionGroup(self, "*Select Final injection(s)*",
        "These options can be used to specify the final code to inject on vulnerable target(s). Important if you want to exploit 'on-the-wild' the vulnerabilities found. Choose only one option:")
        group9.add_option("--Fp", action="store", dest="finalpayload", help="OWN    - Exploit your own code")
        group9.add_option("--Fr", action="store", dest="finalremote", help="REMOTE - Exploit a script -remotely-")
        group9.add_option("--Doss", action="store_true", dest="doss", help="DOSs   - XSS (server) Denial of Service")
        group9.add_option("--Dos", action="store_true", dest="dos", help="DOS    - XSS (client) Denial of Service")
        group9.add_option("--B64", action="store_true", dest="b64", help="B64    - Base64 code encoding in META tag (rfc2397)")
        self.add_option_group(group9)
        
        group10 = optparse.OptionGroup(self, "*Special Final injection(s)*",
        "These options can be used to execute some 'special' injection(s) on vulnerable target(s). You can select multiple and combine them with your final code (except with DCP code):")
        group10.add_option("--Onm", action="store_true", dest="onm", help="ONM - Use onMouseMove() event")
        group10.add_option("--Ifr", action="store_true", dest="ifr", help="IFR - Use <iframe> source tag")
        self.add_option_group(group10)

        group11 = optparse.OptionGroup(self, "*Reporting*")
        group11.add_option("--save", action="store_true", dest="fileoutput", help="export to file (XSSreport.raw)")
        group11.add_option("--xml", action="store", dest="filexml", help="export to XML (--xml file.xml)")
        self.add_option_group(group11)

        group12 = optparse.OptionGroup(self, "*Miscellaneous*")
        group12.add_option("--silent", action="store_true", dest="silent", help="inhibit console output results")
        group12.add_option("--no-head", action="store_true", dest="nohead", help="NOT send a HEAD request before start a test")
        group12.add_option("--alive", action="store", dest="isalive", type="int", help="set limit of errors before check if target is alive")
        group12.add_option("--update", action="store_true", dest="update", help="check for latest stable version")
        self.add_option_group(group12)

    def get_options(self, user_args=None):
        (options, args) = self.parse_args(user_args)
        if (not options.url and not options.readfile and not options.dork and not options.dork_file and not options.imx and not options.flash and not options.update and not options.xsser_gtk and not options.wizard and not options.xst and not options.target):
            print "\n", '='*75
            print self.version
            print "-----------", "\n"
            print self.description, "\n"
            print '='*75
            print ""
            print "                                       \\ \\                           %"
            print "Project site:","                          \\ \\     LulZzzz!           %  "
            print "http://xsser.03c8.net                 %% \\_\\                      %   "
            print "                                      \/ ( \033[1;31m@\033[1;m.\033[1;31m@\033[1;m)         Bbzzzzz!      %  "
            print "                                       \== < ==                  %      "
            print "Forum:                                    / \_      ==       %          "
            print "irc.freenode.net -> #xsser              (')   \   *=====%             "
            print "                                       /  /       ========              "
            print ""
            print '='*75
            print "Total vectors:", self.total_vectors + " = XSS: " + str(self.vectors_fuzz) + " + DCP: " + str(self.vectors_dcp) + " + DOM: " + str(self.vectors_dom) + " + HTTPsr: " + str(self.vectors_httpsr)
            print '='*75
            print "\n-> For HELP use: -h or --help"
            print "\n-> For GTK interface use: --gtk\n"
            print '='*55, "\n"
            return False
        return options
