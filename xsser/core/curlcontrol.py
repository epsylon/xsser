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
import os, urllib, mimetools, pycurl, re, time, random

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

class Curl:
    """
    Class to control curl on behalf of the application.
    """
    cookie = None
    dropcookie = None
    referer = None
    headers = None
    proxy = None
    ignoreproxy = None
    tcp_nodelay = None
    xforw = None
    xclient = None
    atype = None
    acred = None
    #acert = None
    retries = 1
    delay = 0
    followred = 0
    fli = None
    agents = [] # user-agents
    try:
        f = open("core/fuzzing/user-agents.txt").readlines() # set path for user-agents
    except:
        f = open("fuzzing/user-agents.txt").readlines() # set path for user-agents when testing
    for line in f:
        agents.append(line)
    agent = random.choice(agents).strip() # set random user-agent

    def __init__(self, base_url="", fakeheaders=[ 'Accept: image/gif, image/x-bitmap, image/jpeg, image/pjpeg', 'Connection: Keep-Alive', 'Content-type: application/x-www-form-urlencoded; charset=UTF-8']):
        self.handle = pycurl.Curl()
        self._closed = False
        self.set_url(base_url)
        self.verbosity = 0
        self.signals = 1
        self.payload = ""
        self.header = StringIO()
        self.fakeheaders = fakeheaders
        self.headers = None
        self.set_option(pycurl.SSL_VERIFYHOST, 0)
        self.set_option(pycurl.SSL_VERIFYPEER, 0)
        try:
            self.set_option(pycurl.SSLVERSION, pycurl.SSLVERSION_TLSv1_2) # max supported version by pycurl
        except:
            try:
                self.set_option(pycurl.SSLVERSION, pycurl.SSLVERSION_TLSv1_1)
            except: # use vulnerable TLS/SSL versions (TLS1_0 -> weak enc | SSLv2 + SSLv3 -> deprecated)
                try:
                    self.set_option(pycurl.SSLVERSION, pycurl.SSLVERSION_TLSv1_0)
                except:
                    try:
                        self.set_option(pycurl.SSLVERSION, pycurl.SSLVERSION_SSLv3)
                    except:
                        self.set_option(pycurl.SSLVERSION, pycurl.SSLVERSION_SSLv2)
        self.set_option(pycurl.FOLLOWLOCATION, 0)
        self.set_option(pycurl.MAXREDIRS, 50)
        # this is 'black magic'
        self.set_option(pycurl.COOKIEFILE, '/dev/null')
        self.set_option(pycurl.COOKIEJAR, '/dev/null')
        self.set_timeout(30)
        self.set_option(pycurl.NETRC, 1)
        self.set_nosignals(1)

        def payload_callback(x):
            self.payload += x
        self.set_option(pycurl.WRITEFUNCTION, payload_callback)
        def header_callback(x):
            self.header.write(x)
        self.set_option(pycurl.HEADERFUNCTION, header_callback)

    def set_url(self, url):
        """
        Set the base url.
        """
        self.base_url = url
        self.set_option(pycurl.URL, self.base_url)
        return url

    def set_cookie(self, cookie):
        """
        Set the app cookie.
        """
        self.cookie = cookie
        self.dropcookie = dropcookie
        if dropcookie:
            self.set_option(pycurl.COOKIELIST, 'ALL')
            self.set_option(pycurl.COOKIE, None)
        else:
            self.set_option(pycurl.COOKIELIST, '')
            self.set_option(pycurl.COOKIE, self.cookie)
        return cookie

    def set_agent(self, agent):
        """
        Set the user agent.
        """
        self.agent = agent
        self.set_option(pycurl.USERAGENT, self.agent)
        return agent

    def set_referer(self, referer):
        """
        Set the referer.
        """
        self.referer = referer
        self.set_option(pycurl.REFERER, self.referer)
        return referer

    def set_headers(self, headers):
        """
        Set extra headers.
        """
        self.headers = headers
        self.headers = self.headers.split("\n")
        for headerValue in self.headers:
            header, value = headerValue.split(": ")

            if header and value:
                self.set_option(pycurl.HTTPHEADER, (header, value))
        return headers

    def set_proxy(self, ignoreproxy, proxy):
        """
        Set the proxy to use.
        """
        self.proxy = proxy
        self.ignoreproxy = ignoreproxy
        if ignoreproxy:
            self.set_option(pycurl.PROXY, "")
        else:
            self.set_option(pycurl.PROXY, self.proxy)
        return proxy

    def set_option(self, *args):
        """
        Set the given option.
        """
        apply(self.handle.setopt, args)

    def set_verbosity(self, level):
        """
        Set the verbosity level.
        """
        self.set_option(pycurl.VERBOSE, level)

    def set_nosignals(self, signals="1"):
        """
        Disable signals.

        curl will be using other means besides signals to timeout
        """
        self.signals = signals
        self.set_option(pycurl.NOSIGNAL, self.signals)
        return signals

    def set_tcp_nodelay(self, tcp_nodelay):
        """
        Set the TCP_NODELAY option.
        """
        self.tcp_nodelay = tcp_nodelay
        self.set_option(pycurl.TCP_NODELAY, tcp_nodelay)
        return tcp_nodelay

    def set_timeout(self, timeout):
        """
        Set timeout for requests.
        """
        self.set_option(pycurl.CONNECTTIMEOUT,timeout)
        self.set_option(pycurl.TIMEOUT, timeout)
        return timeout

    def set_follow_redirections(self, followred, fli):
        """
        Set follow locations parameters to follow redirection pages (302)
        """
        self.followred = followred
        self.fli = fli
        if followred:
            self.set_option(pycurl.FOLLOWLOCATION , 1)
            self.set_option(pycurl.MAXREDIRS, 50)
            if fli:
                self.set_option(pycurl.MAXREDIRS, fli)
        else:
            self.set_option(pycurl.FOLLOWLOCATION , 0)
        return followred

    def do_head_check(self, urls):
        """
        Send a HEAD request before to start to inject to verify stability of the target
        """
        for u in urls:
            self.set_option(pycurl.URL, u) 
            self.set_option(pycurl.NOBODY,1)
            self.set_option(pycurl.FOLLOWLOCATION, 1)
            self.set_option(pycurl.MAXREDIRS, 50)
            self.set_option(pycurl.SSL_VERIFYHOST, 0)
            self.set_option(pycurl.SSL_VERIFYPEER, 0)
            try:
                self.set_option(pycurl.SSLVERSION, pycurl.SSLVERSION_TLSv1_2) # max supported version by pycurl
            except:
                try:
                    self.set_option(pycurl.SSLVERSION, pycurl.SSLVERSION_TLSv1_1)
                except: # use vulnerable TLS/SSL versions (TLS1_0 -> weak enc | SSLv2 + SSLv3 -> deprecated)
                    try:
                        self.set_option(pycurl.SSLVERSION, pycurl.SSLVERSION_TLSv1_0)
                    except:
                        try:
                            self.set_option(pycurl.SSLVERSION, pycurl.SSLVERSION_SSLv3)
                        except:
                            self.set_option(pycurl.SSLVERSION, pycurl.SSLVERSION_SSLv2)
            if self.fakeheaders:
                from core.randomip import RandomIP
                if self.xforw:
                    generate_random_xforw = RandomIP()
                    xforwip = generate_random_xforw._generateip('')
                    xforwfakevalue = ['X-Forwarded-For: ' + str(xforwip)]
                if self.xclient:
                    generate_random_xclient = RandomIP()
                    xclientip = generate_random_xclient._generateip('')
                    xclientfakevalue = ['X-Client-IP: ' + str(xclientip)]
                if self.xforw:
                    self.set_option(pycurl.HTTPHEADER, self.fakeheaders + xforwfakevalue)
                    if self.xclient:
                        self.set_option(pycurl.HTTPHEADER, self.fakeheaders + xforwfakevalue + xclientfakevalue)
                elif self.xclient:
                    self.set_option(pycurl.HTTPHEADER, self.fakeheaders + xclientfakevalue)
            if self.headers:
                self.fakeheaders = self.fakeheaders + self.headers
            self.set_option(pycurl.HTTPHEADER, self.fakeheaders)
            if self.agent:
                self.set_option(pycurl.USERAGENT, self.agent)
            if self.referer:
                self.set_option(pycurl.REFERER, self.referer)
            if self.proxy:
                self.set_option(pycurl.PROXY, self.proxy)
            if self.ignoreproxy:
                self.set_option(pycurl.PROXY, "")
            if self.timeout:
                self.set_option(pycurl.CONNECTTIMEOUT, self.timeout)
                self.set_option(pycurl.TIMEOUT, self.timeout)
            if self.signals:
                self.set_option(pycurl.NOSIGNAL, self.signals)
            if self.tcp_nodelay:
                self.set_option(pycurl.TCP_NODELAY, self.tcp_nodelay)
            if self.cookie:
                self.set_option(pycurl.COOKIE, self.cookie)
            try:
                self.handle.perform()
            except:
                return
            if str(self.handle.getinfo(pycurl.HTTP_CODE)) in ["302", "301"]:
                self.set_option(pycurl.FOLLOWLOCATION, 1)

    def __request(self, relative_url=None):
        """
        Perform a request and returns the payload.
        """
        if self.fakeheaders:
            from core.randomip import RandomIP
            if self.xforw:
                """
                Set the X-Forwarded-For to use.
                """
                generate_random_xforw = RandomIP()
                xforwip = generate_random_xforw._generateip('')
                xforwfakevalue = ['X-Forwarded-For: ' + str(xforwip)]
            if self.xclient:
                """ 
                Set the X-Client-IP to use.
                """
                generate_random_xclient = RandomIP()
                xclientip = generate_random_xclient._generateip('')
                xclientfakevalue = ['X-Client-IP: ' + str(xclientip)]
            if self.xforw:
                self.set_option(pycurl.HTTPHEADER, self.fakeheaders + xforwfakevalue)
                if self.xclient:
                    self.set_option(pycurl.HTTPHEADER, self.fakeheaders + xforwfakevalue + xclientfakevalue)
            elif self.xclient:
                self.set_option(pycurl.HTTPHEADER, self.fakeheaders + xclientfakevalue)
        if self.headers:
            self.fakeheaders = self.fakeheaders + self.headers
        self.set_option(pycurl.HTTPHEADER, self.fakeheaders)
        if self.agent:
            self.set_option(pycurl.USERAGENT, self.agent)
        if self.referer:
            self.set_option(pycurl.REFERER, self.referer)
        if self.proxy:
            self.set_option(pycurl.PROXY, self.proxy)
        if self.ignoreproxy:
            self.set_option(pycurl.PROXY, "")
        if relative_url:
            self.set_option(pycurl.URL,os.path.join(self.base_url,relative_url))
        if self.timeout:
            self.set_option(pycurl.CONNECTTIMEOUT, self.timeout)
            self.set_option(pycurl.TIMEOUT, self.timeout)
        if self.signals:
            self.set_option(pycurl.NOSIGNAL, self.signals)
        if self.tcp_nodelay:
            self.set_option(pycurl.TCP_NODELAY, self.tcp_nodelay)
        if self.cookie:
            self.set_option(pycurl.COOKIE, self.cookie)
        if self.followred:
            self.set_option(pycurl.FOLLOWLOCATION , 1)
            self.set_option(pycurl.MAXREDIRS, 50)
            if self.fli:
                self.set_option(pycurl.MAXREDIRS, int(self.fli))
        else:
            self.set_option(pycurl.FOLLOWLOCATION , 0)
            if self.fli:
                print "\n[E] You must launch --follow-redirects command to set correctly this redirections limit\n"
                return
        """ 
        Set the HTTP authentication method: Basic, Digest, GSS, NTLM or Certificate
        """
        if self.atype and self.acred:
            atypelower = self.atype.lower()
            if atypelower not in ( "basic", "digest", "ntlm", "gss" ):
                print "\n[E] HTTP authentication type value must be: Basic, Digest, GSS or NTLM\n"
                return
            acredregexp = re.search("^(.*?)\:(.*?)$", self.acred)
            if not acredregexp:
                print "\n[E] HTTP authentication credentials value must be in format username:password\n"
                return
            user = acredregexp.group(1)
            password = acredregexp.group(2)
            self.set_option(pycurl.USERPWD, "%s:%s" % (user,password))
            if atypelower == "basic":
                self.set_option(pycurl.HTTPAUTH, pycurl.HTTPAUTH_BASIC)
            elif atypelower == "digest":
                self.set_option(pycurl.HTTPAUTH, pycurl.HTTPAUTH_DIGEST)
            elif atypelower == "ntlm":
                self.set_option(pycurl.HTTPAUTH, pycurl.HTTPAUTH_NTLM)
            elif atypelower == "gss":
                self.set_option(pycurl.HTTPAUTH, pycurl.HTTPAUTH_GSSNEGOTIATE)
            else:
                self.set_option(pycurl.HTTPAUTH, None)
            self.set_option(pycurl.HTTPHEADER, ["Accept:"])
        elif self.atype and not self.acred:
            print "\n[E] You specified the HTTP authentication type, but did not provide the credentials\n"
            return
        elif not self.atype and self.acred:
            print "\n[E] You specified the HTTP authentication credentials, but did not provide the type\n"
            return
        #if self.acert:
        #    acertregexp = re.search("^(.+?),\s*(.+?)$", self.acert)
        #    if not acertregexp:
        #        print "\n[E] HTTP authentication certificate option must be 'key_file,cert_file'\n"
        #        return
        #    # os.path.expanduser for support of paths with ~
        #    key_file = os.path.expanduser(acertregexp.group(1))
        #    cert_file = os.path.expanduser(acertregexp.group(2))
        #    self.set_option(pycurl.SSL_VERIFYHOST, 0)
        #    self.set_option(pycurl.SSL_VERIFYPEER, 1)
        #    self.set_option(pycurl.SSH_PUBLIC_KEYFILE, key_file)
        #    self.set_option(pycurl.CAINFO, cert_file)
        #    self.set_option(pycurl.SSLCERT, cert_file)
        #    self.set_option(pycurl.SSLCERTTYPE, 'p12')
        #    self.set_option(pycurl.SSLCERTPASSWD, '1234')
        #    self.set_option(pycurl.SSLKEY, key_file)
        #    self.set_option(pycurl.SSLKEYPASSWD, '1234')
        #    for file in (key_file, cert_file):
        #        if not os.path.exists(file):
        #            print "\n[E] File '%s' doesn't exist\n" % file
        #            return
        self.set_option(pycurl.SSL_VERIFYHOST, 0)
        self.set_option(pycurl.SSL_VERIFYPEER, 0)
        self.header.seek(0,0)
        self.payload = ""
        for count in range(0, self.retries):
            time.sleep(self.delay)
            if self.dropcookie:
                self.set_option(pycurl.COOKIELIST, 'ALL')
                nocookie = ['Set-Cookie: ', '']
                self.set_option(pycurl.HTTPHEADER, self.fakeheaders + nocookie)
            try:
                self.handle.perform()
            except:
                return
        return self.payload

    def get(self, url="", params=None):
        """
        Get a url.
        """
        if params:
            url += "?" + urllib.urlencode(params)
        self.set_option(pycurl.HTTPGET, 1)
        return self.__request(url)

    def post(self, cgi, params):
        """
        Post a url.
        """
        self.set_option(pycurl.POST, 1)
        self.set_option(pycurl.POSTFIELDS, params)
        return self.__request(cgi)

    def body(self):
        """
        Get the payload from the latest operation.
        """
        return self.payload

    def info(self):
        """
        Get an info dictionary from the selected url.
        """
        self.header.seek(0,0)
        url = self.handle.getinfo(pycurl.EFFECTIVE_URL)
        if url[:5] == 'http:':
            self.header.readline()
            m = mimetools.Message(self.header)
        else:
            m = mimetools.Message(StringIO())
        #m['effective-url'] = url
        m['http-code'] = str(self.handle.getinfo(pycurl.HTTP_CODE))
        m['total-time'] = str(self.handle.getinfo(pycurl.TOTAL_TIME))
        m['namelookup-time'] = str(self.handle.getinfo(pycurl.NAMELOOKUP_TIME))
        m['connect-time'] = str(self.handle.getinfo(pycurl.CONNECT_TIME))
        #m['pretransfer-time'] = str(self.handle.getinfo(pycurl.PRETRANSFER_TIME))
        #m['redirect-time'] = str(self.handle.getinfo(pycurl.REDIRECT_TIME))
        #m['redirect-count'] = str(self.handle.getinfo(pycurl.REDIRECT_COUNT))
        #m['size-upload'] = str(self.handle.getinfo(pycurl.SIZE_UPLOAD))
        #m['size-download'] = str(self.handle.getinfo(pycurl.SIZE_DOWNLOAD))
        #m['speed-upload'] = str(self.handle.getinfo(pycurl.SPEED_UPLOAD))
        m['header-size'] = str(self.handle.getinfo(pycurl.HEADER_SIZE))
        m['request-size'] = str(self.handle.getinfo(pycurl.REQUEST_SIZE))
        m['response-code'] = str(self.handle.getinfo(pycurl.RESPONSE_CODE))
        m['ssl-verifyresult'] = str(self.handle.getinfo(pycurl.SSL_VERIFYRESULT))
        m['content-type'] = (self.handle.getinfo(pycurl.CONTENT_TYPE) or '').strip(';')
        m['cookielist'] = str(self.handle.getinfo(pycurl.INFO_COOKIELIST))
        #m['content-length-download'] = str(self.handle.getinfo(pycurl.CONTENT_LENGTH_DOWNLOAD))
        #m['content-length-upload'] = str(self.handle.getinfo(pycurl.CONTENT_LENGTH_UPLOAD))
        #m['encoding'] = str(self.handle.getinfo(pycurl.ENCODING))
        return m

    @classmethod
    def print_options(cls):
        """
        Print selected options.
        """
        print "\n[-]Verbose: active"
        print "[-]Cookie:", cls.cookie
        print "[-]HTTP User Agent:", cls.agent
        print "[-]HTTP Referer:", cls.referer
        print "[-]Extra HTTP Headers:", cls.headers
        if cls.xforw == True:
            print "[-]X-Forwarded-For:", "Random IP"
        else:
            print "[-]X-Forwarded-For:", cls.xforw
        if cls.xclient == True:
            print "[-]X-Client-IP:", "Random IP"
        else:
            print "[-]X-Client-IP:", cls.xclient
        print "[-]Authentication Type:", cls.atype
        print "[-]Authentication Credentials:", cls.acred
        if cls.ignoreproxy == True:
            print "[-]Proxy:", "Ignoring system default HTTP proxy"
        else:
            print "[-]Proxy:", cls.proxy
        print "[-]Timeout:", cls.timeout
        if cls.tcp_nodelay == True:
            print "[-]Delaying:", "TCP_NODELAY activate"
        else:
            print "[-]Delaying:", cls.delay, "seconds"
        if cls.followred == True:
            print "[-]Follow 302 code:", "active"
            if cls.fli:
                print"[-]Limit to follow:", cls.fli
        else:
            print "[-]Delaying:", cls.delay, "seconds"

        print "[-]Retries:", cls.retries, "\n"

    def answered(self, check):
        """
        Check for occurence of a string in the payload from
        the latest operation.
        """
        return self.payload.find(check) >= 0

    def close(self):
        """
        Close the curl handle.
        """
        self.handle.close()
        self.header.close()
        self._closed = True

    def __del__(self):
        if not self._closed:
            self.close()
