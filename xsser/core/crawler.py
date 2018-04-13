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
import sys
import urllib
import urllib2
import urlparse
import pycurl
import time
import traceback
import curlcontrol
import threadpool
from Queue import Queue
from collections import defaultdict
from BeautifulSoup import BeautifulSoup

class EmergencyLanding(Exception):
    pass

class Crawler(object):
    """
    Crawler class.

    Crawls a webpage looking for url arguments.
    Dont call from several threads! You should create a new one
    for every thread.
    """
    def __init__(self, parent, curlwrapper=None, crawled=None, pool=None):
        # verbose: 0-no printing, 1-prints dots, 2-prints full output
        self.verbose = 1
        self._parent = parent
        self._to_crawl = []
        self._parse_external = True
        self._requests = []
        self._ownpool = False
        self._reporter = None
        self._armed = True
        self._poolsize = 10
        self._found_args = defaultdict(list)
        self.pool = pool
        if crawled:
            self._crawled = crawled
        else:
            self._crawled = []
        if curlwrapper:
            self.curl = curlwrapper
        else:
            self.curl = curlcontrol.Curl

    def report(self, msg):
        if self._reporter:
            self._reporter.report(msg)
        else:
            print msg

    def set_reporter(self, reporter):
        self._reporter = reporter

    def _find_args(self, url):
        """
        find parameters in given url.
        """
        parsed = urllib2.urlparse.urlparse(url)
        qs = urlparse.parse_qs(parsed.query)
        if parsed.scheme:
            path = parsed.scheme + "://" + parsed.netloc + parsed.path
        else:
            path = parsed.netloc + parsed.path
        for arg_name in qs:
            key = (arg_name, parsed.netloc)
            zipped = zip(*self._found_args[key])
            if not zipped or not path in zipped[0]:
                self._found_args[key].append([path, url])
                self.generate_result(arg_name, path, url)
        ncurrent = sum(map(lambda s: len(s), self._found_args.values()))
        if ncurrent >= self._max:
            self._armed = False

    def cancel(self):
        self._armed = False

    def crawl(self, path, depth=3, width=0, local_only=True):
        """
        setup and perform a crawl on the given url.
        """
        if not self._armed:
            return []
        parsed = urllib2.urlparse.urlparse(path)
        basepath = parsed.scheme + "://" + parsed.netloc
        self._parse_external = not local_only
        if not self.pool:
            self.pool = threadpool.ThreadPool(self._poolsize)
        if self.verbose == 2:
            self.report("crawling: " + path)
        if width == 0:
            self._max = 1000000000
        else:
            self._max = int(width)
        self._path = path
        self._depth = depth
        attack_urls = []
        if not self._parent._landing and self._armed:
            self._crawl(basepath, path, depth, width)
            if self._ownpool:
                self.pool.dismissWorkers(len(self.pool.workers))
                self.pool.joinAllDismissedWorkers()
        return attack_urls

    def shutdown(self):
        if self._ownpool:
            self.pool.dismissWorkers(len(self.pool.workers))
            self.pool.joinAllDismissedWorkers()

    def generate_result(self, arg_name, path, url):
        parsed = urllib2.urlparse.urlparse(url)
        qs = urlparse.parse_qs(parsed.query)
        qs_joint = {}
        for key, val in qs.iteritems():
            qs_joint[key] = val[0]
        attack_qs = dict(qs_joint)
        attack_qs[arg_name] = "VECTOR"
        attack_url = path + '?' + urllib.urlencode(attack_qs)
        if not attack_url in self._parent.crawled_urls:
            self._parent.crawled_urls.append(attack_url)

    def _crawl(self, basepath, path, depth=3, width=0):
        """
        perform a crawl on the given url.

        this function downloads and looks for links.
        """
        self._crawled.append(path)
        if not path.startswith("http"):
            return

        def _cb(request, result):
            self._get_done(depth, width, request, result)

        self._requests.append(path)
        self.pool.addRequest(self._curl_main, [[path, depth, width, basepath]],
                             self._get_done_dummy, self._get_error)

    def _curl_main(self, pars):
        path, depth, width, basepath = pars
        if not self._armed or len(self._parent.crawled_urls) >= self._max:
            raise EmergencyLanding
        c = self.curl()
        c.set_timeout(5)
        try:
            res = c.get(path)
        except Exception as error:
            c.close()
            del c
            raise error
        c_info = c.info().get('content-type', None)
        c.close()
        del c
        self._get_done(basepath, depth, width, path, res, c_info)

    def _get_error(self, request, error):
        try:
            path, depth, width, basepath = request.args[0]
            e_type, e_value, e_tb = error
            if e_type == pycurl.error:
                errno, message = e_value.args
                if errno == 28:
                    print("requests pyerror -1")
                    self.enqueue_jobs()
                    self._requests.remove(path)
                    return # timeout
                else:
                    self.report('crawler curl error: '+message+' ('+str(errno)+')')
            elif e_type == EmergencyLanding:
                pass
            else:
                traceback.print_tb(e_tb)
                self.report('crawler error: '+str(e_value)+' '+path)
            if not e_type == EmergencyLanding:
                for reporter in self._parent._reporters:
                    reporter.mosquito_crashed(path, str(e_value))
            self.enqueue_jobs()
            self._requests.remove(path)
        except:
            return

    def _emergency_parse(self, html_data, start=0):
        links = set()
        pos = 0
        if not html_data:
            return
        data_len = len(html_data)
        while pos < data_len:
            if len(links)+start > self._max:
                break
            pos = html_data.find("href=", pos)
            if not pos == -1:
                sep = html_data[pos+5]
                if sep == "h":
                    pos -= 1
                    sep=">"
                href = html_data[pos+6:html_data.find(sep, pos+7)].split("#")[0]
                pos = pos+1
                links.add(href)
            else:
                break
        return map(lambda s: {'href': s}, links)

    def _get_done_dummy(self, request, result):
        path = request.args[0][0]
        self.enqueue_jobs()
        self._requests.remove(path)

    def enqueue_jobs(self):
        if len(self.pool.workRequests) < int(self._max/2):
            while self._to_crawl:
                next_job = self._to_crawl.pop()
                self._crawl(*next_job)

    def _get_done(self, basepath, depth, width, path, html_data, content_type): # request, result):
        if not self._armed or len(self._parent.crawled_urls) >= self._max:
            raise EmergencyLanding
        try:
            encoding = content_type.split(";")[1].split("=")[1].strip()
        except:
            encoding = None
        try:
            soup = BeautifulSoup(html_data, from_encoding=encoding)
            links = None
        except:
            soup = None
            links = self._emergency_parse(html_data)

        for reporter in self._parent._reporters:
            reporter.start_crawl(path)

        if not links and soup:
            links = soup.find_all('a')
            forms = soup.find_all('form')

            for form in forms:
                pars = {}
                if form.has_key("action"):
                    action_path = urlparse.urljoin(path, form["action"])
                else:
                    action_path = path
                for input_par in form.find_all('input'):

                    if not input_par.has_key("name"):
                        continue
                    value = "foo"
                    if input_par.has_key("value") and input_par["value"]:
                        value = input_par["value"]
                    pars[input_par["name"]] = value
                for input_par in form.findAll('select'):
                    pars[input_par["name"]] = "1"
                if pars:
                    links.append({"url":action_path + '?' + urllib.urlencode(pars)})
                else:
                    self.report("form with no pars")
                    links.append({"url":action_path})
            links += self._emergency_parse(html_data, len(links))
        if self.verbose == 2:
            self.report(" "*(self._depth-depth) + path +" "+ str(len(links)))
        elif self.verbose:
            sys.stdout.write(".")
            sys.stdout.flush()
        if not links:
            return
        if len(links) > self._max:
            links = links[:self._max]
        for a in links:
            try:
                href = str(a['href'].encode('utf-8'))
            except KeyError:
                # this link has no href
                continue
            except:
                # can't decode or something darker..
                continue
            if href.startswith("javascript") or href.startswith('mailto:'):
                continue
            href = urlparse.urljoin(path, href)
            if not href.startswith("http") or not "." in href:
                continue
            href = href.split('#',1)[0]
            scheme_rpos = href.rfind('http://')
            if not scheme_rpos in [0, -1]:
                # looks like some kind of redirect so we try both too ;)
                href1 = href[scheme_rpos:]
                href2 = href[:scheme_rpos]
                self._check_url(basepath, path, href1, depth, width)
                self._check_url(basepath, path, href2, depth, width)
            self._check_url(basepath, path, href, depth, width)
        return self._found_args

    def _check_url(self, basepath, path, href, depth, width):
        """
        process the given url for a crawl
        check to see if we have to continue crawling on the given url.
        """
        do_crawling = self._parse_external or href.startswith(basepath)
        if do_crawling and not href in self._crawled:
            self._find_args(href)
            for reporter in self._parent._reporters:
                reporter.add_link(path, href)
            self.report("\n[Info] Spidering: " + str(href))
            if self._armed and depth>0:
                if len(self._to_crawl) < self._max:
                    self._to_crawl.append([basepath, href, depth-1, width])
