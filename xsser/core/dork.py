#!/usr/bin/env python
# -*- coding: utf-8 -*-"
# vim: set expandtab tabstop=4 shiftwidth=4:
"""
This file is part of the xsser project, https://xsser.03c8.net

Copyright (c) 2011/2016/2018 psy <epsylon@riseup.net>

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
........

List of search engines: http://en.wikipedia.org/wiki/List_of_search_engines

"""
import urllib2, traceback, re, random
urllib2.socket.setdefaulttimeout(5.0)

DEBUG = 0

class Dorker(object):
    def __init__(self, engine='yahoo'):
        self._engine = engine
        self.search_engines = [] # available dorking search engines
        self.search_engines.append('bing')
        self.search_engines.append('yahoo')
        self.agents = [] # user-agents
        try:
            f = open("core/fuzzing/user-agents.txt").readlines() # set path for user-agents
        except:
            f = open("fuzzing/user-agents.txt").readlines() # set path for user-agents when testing
        for line in f:
            self.agents.append(line)

    def dork(self, search):
        """
        Perform a search and return links.
        """
        if self._engine == 'bing': # works at 20-02-2011 -> 19-02-2016 -> 09-04-2018
            search_url = 'https://www.bing.com/search?q="' + search + '"'
        elif self._engine == 'yahoo': # works at 20-02-2011 -> 19-02-2016 -> -> 09-04-2018
            search_url = 'https://search.yahoo.com/search?q="' + search + '"'
        else:
            print "\n[Error] This search engine is not supported!\n" 
            print "[Info] List of available:"
            print '-'*25
            for e in self.search_engines:
                print "+ "+e
            print ""
        try:
            self.search_url = search_url
            print "\n[Info] Search query:", urllib2.unquote(search_url)
            user_agent = random.choice(self.agents).strip() # set random user-agent
            referer = '127.0.0.1' # set referer to localhost / WAF black magic!
            headers = {'User-Agent' : user_agent, 'Referer' : referer}
            req = urllib2.Request(search_url, None, headers)
            html_data = urllib2.urlopen(req).read()
            print "\n[Info] Retrieving requested info..."
        except urllib2.URLError, e:
            if DEBUG:
                traceback.print_exc()
            print "\n[Error] Cannot connect!"
            return
        if self._engine == 'bing':
            regex = '<h2><a href="(.+?)" h=' # regex magics 09-04/2018
        if self._engine == 'yahoo':
            regex = 'RU=(.+?)/RK=' # regex magics [09/04/2018]
        pattern = re.compile(regex)
        links = re.findall(pattern, html_data)
        found_links = []
        if links:
            for link in links:
                link = urllib2.unquote(link)
                if self._engine == "yahoo":
                    if "RU=https://www.yahoo.com/" in link:
                        link = "" # invalid url
                if search.upper() in link.upper(): # parse that search query is on url
                    sep = search
                    link2 = link.split(sep,1)[0]
                    if link2 not in found_links: # parse that target is not duplicated
                        found_links.append(link)
        else:
            print "\n[Info] Not any link found for that query!"
        return found_links

if __name__ == '__main__':
    for a in ['yahoo', 'bing']:
        dork = Dorker(a)
        res = dork.dork("news.php?id=")
        if res:
            print "[+]", a, ":", len(res), "\n"
            for b in res:
                print " *", b
