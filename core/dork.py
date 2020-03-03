#!/usr/bin/env python
# -*- coding: utf-8 -*-"
# vim: set expandtab tabstop=4 shiftwidth=4:
"""
This file is part of the XSSer project, https://xsser.03c8.net

Copyright (c) 2010/2020 | psy <epsylon@riseup.net>

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

List of search engines: https://en.wikipedia.org/wiki/List_of_search_engines

Currently supported: duck(default), startpage, yahoo, bing

"""
import urllib.request, urllib.error, urllib.parse, traceback, re, random
urllib.request.socket.setdefaulttimeout(5.0)

DEBUG = 0

class Dorker(object):
    def __init__(self, engine='duck'):
        self._engine = engine
        self.search_engines = [] # available dorking search engines
        self.search_engines.append('duck')
        self.search_engines.append('startpage')
        self.search_engines.append('yahoo')
        self.search_engines.append('bing')
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
        if self._engine == 'bing': # works at 20-02-2011 -> 19-02-2016 -> 09-04-2018 -> 26-08-2019
            search_url = 'https://www.bing.com/search?q="' + str(search) + '"'
            print("\nSearching query:", urllib.parse.unquote(search_url))
        elif self._engine == 'yahoo': # works at 20-02-2011 -> 19-02-2016 -> -> 09-04-2018 -> 26-08-2019
            search_url = 'https://search.yahoo.com/search?q="' + str(search) + '"'
            print("\nSearching query:", urllib.parse.unquote(search_url))
        elif self._engine == 'duck': # works at 26-08-2019
            search_url = 'https://duckduckgo.com/html/' 
            q = 'instreamset:(url):"' + str(search) + '"' # set query to search literally on results
            query_string = { 'q':q }
            print("\nSearching query:", urllib.parse.unquote(search_url) + " [POST: (" + q + ")]")
        elif self._engine == 'startpage': # works at 26-08-2019
            search_url = 'https://www.startpage.com/do/asearch'
            q = 'url:"' + str(search) + '"' # set query to search literally on results
            query_string = { 'cmd':'process_search', 'query':q }
            print("\nSearching query:", urllib.parse.unquote(search_url) + " [POST: (" + q + ")]")
        else:
            print("\n[Error] This search engine is not being supported!\n")
            print('-'*25) 
            print("\n[Info] Use one from this list:\n")
            for e in self.search_engines:
                print("+ "+e)
            print("\n ex: xsser -d 'profile.asp?num=' --De 'duck'")
            print(" ex: xsser -l --De 'startpage'")
            print("\n[Info] Or try them all:\n\n ex: xsser -d 'news.php?id=' --Da\n")
        try:
            self.search_url = search_url
            user_agent = random.choice(self.agents).strip() # set random user-agent
            referer = '127.0.0.1' # set referer to localhost / WAF black magic!
            headers = {'User-Agent' : user_agent, 'Referer' : referer}
            if self._engine == 'bing' or self._engine == 'yahoo': # using GET
                req = urllib.request.Request(search_url, None, headers)
            elif self._engine == 'duck' or self._engine == 'startpage': # using POST
                data = urllib.parse.urlencode(query_string)
                req = urllib.request.Request(search_url, data, headers)
            html_data = urllib.request.urlopen(req).read().decode('utf8')
            print("\n[Info] Retrieving requested info...\n")
        except urllib.error.URLError as e:
            if DEBUG:
                traceback.print_exc()
            print("\n[Error] Cannot connect!")
            print("\n" + "-"*50)
            return
        if self._engine == 'bing':
            regex = '<h2><a href="(.+?)" h=' # regex magics 08/2019
        if self._engine == 'yahoo':
            regex = 'RU=(.+?)/RK=' # regex magics 08/2019
        if self._engine == 'duck':
            regex = '<a class="result__url" href="(.+?)">' # regex 08/2019
        if self._engine == 'startpage':
            regex = 'target="_blank">(.+?)</a>' # regex magics 08/2019
        pattern = re.compile(regex)
        links = re.findall(pattern, html_data, flags=0)
        found_links = []
        if links:
            for link in links:
                link = urllib.parse.unquote(link)
                if self._engine == "yahoo":
                    if "RU=https://www.yahoo.com/" in link:
                        link = "" # invalid url
                if search.upper() in link.upper(): # parse that search query is on url
                    sep = search
                    link2 = link.split(sep,1)[0]
                    if link2 not in found_links: # parse that target is not duplicated
                        found_links.append(link)
        else:
            print("\n[Error] Not any link found for that query!")
        return found_links

if __name__ == '__main__':
    for a in ['bing', 'yahoo', 'duck', 'startpage']: # working at: 28/08/2019
        dork = Dorker(a)
        res = dork.dork("news.php?id=")
        if res:
            print("\n[+] Search Engine:", a, "| Found: ", len(res), "\n")
            for b in res:
                print(" *", b)
