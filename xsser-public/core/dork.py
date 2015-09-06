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
import urlparse
import urllib2
import traceback
urllib2.socket.setdefaulttimeout(5.0)
from BeautifulSoup import BeautifulSoup

DEBUG = 1

class Dorker(object):
    def __init__(self, engine='bing'):
        self._engine = engine

    def dork(self, search):
        """
        Perform a search and return links.

        Uses -bing- engine by default.

	(http://en.wikipedia.org/wiki/List_of_search_engines)
        """
        urlpar = None
        divid = None
        unpack_func = None
        css_class = None
        raw_extract = None
        html_tok = 'a'
        paging_arg = None # allow to do paging
        if self._engine == 'bing' or not self._engine: # works at 20-02-2011
            search_url = "http://www.bing.com/search?q=" + urllib2.quote(search)
            divid = 'results_container'
        elif self._engine == 'scroogle':
            search_url = "http://www.scroogle.org/cgi-bin/nbbw.cgi?q=" + urllib2.quote(search)
        elif self._engine == 'altavista': # works at 20-02-2011
            def altavista_func(href):
                href = href['href']
                # http://search.yahoo.com/r/_ylt=A0oG7p45zGBNl0MAuhQPxQt.;_ylu=X3oDMTByMTNuNTZzBHNlYwNzcgRwb3MDMgRjb2xvA2FjMgR2dGlkAw--/SIG=11942um5m/EXP=1298275769/**http%3a//money.cnn.com/
                if "**" in href:
                    return {'href':urlparse.unquote(href[href.rfind('**')+2:])}
            #divid = 'results' -> in other altavista=?
            def raw_extract(html_data, encoding):
                results = []
                for line in html_data.split("\n"):
                    if "<a class='res'" in line and "http" in line:
                        href = line[line.find("http"):line.rfind("'")]
                        results.append({'href': href})
                return results
            css_class = 'res'
            #unpack_func = altavista_func -> in otherS?
            #search_url = "http://us.yhs4.search.yahoo.com/yhs/search?fr=altavista&itag=ody&q=" + urllib2.quote(search)
            search_url = "http://es.altavista.com/web/results?fr=altavista&itag=ody&q=" + urllib2.quote(search)
        elif self._engine == 'duck': # seems hopeless at 20-02-2011
            search_url = "https://duckduckgo.com/?q=" + urllib2.quote(search)
        elif self._engine == 'baidu': # works at 20-02-2011
            #html_tok = 'span'
            #css_class = 'g'
            def raw_extract(html_data, encoding):
                results = []
                pos = 0 
                while pos < len(html_data):
                    pos = html_data.find('span class="g">', pos)
                    if pos == -1:
                        break;
                    href = html_data[pos+15:html_data.find('<', pos)].strip()
                    pos = pos + 1
                    if not href:
                        continue
                    href = href.split(" ")[0]
                    if not href.startswith('http'):
                        href = 'http://'+href
                    results.append({'href': href})
                return results

            search_url = "http://www.baidu.com/s?wd=" + urllib2.quote(search)
        elif self._engine == 'yandex': # works at 20-02-2011
            def raw_extract(html_data, encoding):
                results = []
                for line in html_data.split("\n"):
                    if 'class="b-serp-url__link"' in line and "http" in line:
                        href = line[line.find("http"):line.find('"', line.find("http")+10)]
                        results.append({'href': href})
                return results
            #css_class = 'b-serp-url__link'
            search_url = "http://yandex.ru/yandsearch?text=" + urllib2.quote(search)
        elif self._engine == 'yebol':
            divid = "Scrollbar-SearchResultsc"
            search_url = "http://www.yebol.com/a.jsp?x=0&y=0&key=" + urllib2.quote(search)
        elif self._engine == 'youdao':
            search_url = "http://www.youdao.com/search?q=" + urllib2.quote(search)
        #elif self._engine == 'ask': # not works
        #    def raw_extract(html_data, encoding):
        #        results = []
        #        prevline = ""
        #        for line in html_data.split("\n"):
        #            if 'class="title txt_lg"' in line and "http" in prevline:
        #                href = prevline[prevline.find("http"):prevline.find('"',
        #                                                                    prevline.find("http")+10)]
        #                results.append({'href': href})
        #            prevline = line
        #        return results
        #    search_url = "http://www.ask.com/web?q=" + urllib2.quote(search)
        elif self._engine == 'google': # works at 11/11/2011
            #def raw_extract(html_data, encoding):
            #    results = []
            #    prevline = ""
            #    for line in html_data.split("\n"):
            #        if 'class="r"' in line and "http" in prevline:
            #            href = prevline[prevline.find("http"):prevline.find('"',
            #                                                                prevline.find("http")+10)]
            #            results.append({'href': href})
            #        prevline = line
            #    return results
            search_url = "https://encrypted.google.com/search?hl=en&q=" + urllib2.quote(search)
        elif self._engine == 'yahoo': # works at 20-02-2011
            def raw_extract(html_data, encoding):
                results = []
                for line in html_data.split("\n"):
                    if 'class="yschttl spt"' in line and "http" in line:
                        href = line[line.find("http"):line.find('"', line.find("http")+10)]
                        results.append({'href': href})
                return results
            search_url = "http://search.yahoo.com/search?p=" + urllib2.quote(search)
        elif self._engine == 'sogou':
            search_url = "http://www.sogou.com/web?query=" + urllib2.quote(search)
        elif self._engine == 'rediff':
            search_url = "http://search1.rediff.com/dirsrch/default.asp?src=web&MT=" + urllib2.quote(search)
        elif self._engine == 'blekko':
            search_url = "http://blekko.com/ws/?q=" + urllib2.quote(search)
        elif self._engine == 'kosmix': # doesnt work properly
            def raw_extract(html_data, encoding):
                print html_data
                results = []
                is_next = False
                for line in html_data.split("\n"):
                    #if 'class="www_result_url"' in line and "http" in line:
                    if '<h4>' in line and "http" in line:
                        href = line[line.find("http"):line.find('"', line.find("http")+10)]
                        results.append({'href': href})
                        is_next=False
                    if is_next and "http" in line:
                        href = line[line.find("http"):line.find('"', line.find("http")+10)]
                        results.append({'href': href})
                        is_next=False
                    elif '<h4>' in line:
                        is_next=True
                    else:
                        is_next=False
                return results
            search_url = "http://www.kosmix.com/topic/lala?q=" + urllib2.quote(search)
        elif self._engine == 'search': # works at 20-02-2011
            def raw_extract(html_data, encoding):
                results = []
                for line in html_data.split("\n"):
                    if 'class="www_result_url"' in line and "http" in line:
                    #if 'class="www_result_title"' in line and "http" in line:
                        href = line[line.find("http"):line.find('"', line.find("http")+10)]
                        results.append({'href': href})
                return results
            search_url = "http://www.search.ch/?q=" + urllib2.quote(search)
        elif self._engine == 'ifacnet':
            search_url = "http://www.ifacnet.com/?q=" +  urllib2.quote(search)
        elif self._engine == 'bussines':
            search_url = "http://www.business.com/search/rslt_default.asp?vt=all&type=web&query=" + urllib2.quote(search)
        elif self._engine == 'globalspec':
            search_url = "http://search.globalspec.com/Search?query=" + urllib2.quote(search)
        elif self._engine == 'taptu':
            search_url = "http://www.taptu.com/search/lite/results?term=" + urllib2.quote(search)
        elif self._engine == 'topix':
            search_url = "http://www.topix.com/search/article?q=" + urllib2.quote(search)
        elif self._engine == 'hakia':
            search_url = "http://hakia.com/search?q=" + urllib2.quote(search)
        elif self._engine == 'leapfish':
            search_url = "http://www.leapfish.com/web.aspx?q=" + urllib2.quote(search)
        #elif self._engine == 'webcrawler': # works at 20-02-2011
        #    urlpar = "rawURL"
        #    search_url = "http://www.webcrawler.com/webcrawler203/ws/results/Web/" + urllib2.quote(search) + "/1/417/TopNavigation/Relevance/iq=true/zoom=off/_iceUrlFlag=7?_IceUrl=true"
        elif self._engine == 'excite':
            search_url = "http://msxml.excite.com/excite/ws/results/Web/" + urllib2.quote(search) + "/1/0/0/Relevance/iq=true/zoom=off/_iceUrlFlag=7?_IceUrl=true" 
        elif self._engine == 'yolink':
            search_url = "http://cloud.yolink.com/search/search?keywords=" + urllib2.quote(search)
        elif self._engine == 'lycos':
            search_url = "http://search.lycos.com/?tab=web&query=" + urllib2.quote(search)
        else:
            print "\nThis search engine is not allowed. Check dork.py file to see a complete list\n"
        try:
            self.search_url = search_url
            url = urllib2.urlopen(urllib2.Request(search_url,
                                                  headers={'User-Agent':
                            "Googlebot/2.1 (+http://www.google.com/bot.html"}))
        except urllib2.URLError, e:
            if DEBUG:
                traceback.print_exc()
            raise Exception("Internal error dorking: " + e.message)
        html_data = url.read()
        html_data = html_data.replace(">",">\n")
        html_data = html_data.replace("target=_",'target="_')
        html_data = html_data.replace('\ >','/>')
        html_data = html_data.replace('\>','/>')
        html_data = html_data.replace('"">','">')
        html_data = html_data.replace('</scr"+"ipt>','</script>')
        content_type = url.headers['content-type']
        try:
            encoding = content_type.split(";")[1].split("=")[1].strip()
        except:
            encoding = 'utf-8'
        if raw_extract:
            links = raw_extract(html_data, encoding)
        else:
            try:
                soup = BeautifulSoup(html_data, fromEncoding=encoding)
            except Exception, e:
                traceback.print_exc()
                raise Exception("Internal error dorking:" + e.message)

            if divid:
                #print(html_data)
                soup = soup.find('div', {'id':divid})
            if css_class:
                links = soup.findAll(html_tok, {'class':css_class})
            else:
                links = soup.findAll(html_tok)
        found_links = []
        if unpack_func:
            links = map(unpack_func, links)
            links = filter(lambda s: s, links)
        for link in links:
            try:
                href = str(link['href'].encode('utf-8'))
            except KeyError:
                # this link has no href
                pass
            else:
                if not href.startswith("/") and not "microsofttranslator" in href and not "bingj" in href and not "live.com" in href and not "scroogle" in href:
                    if urlpar:
                        parsed = urlparse.urlparse(href)
                        q = urlparse.parse_qs(parsed.query)
                        if urlpar in q and q[urlpar]:
                            href = urlparse.unquote(q[urlpar][0])
                            found_links.append(href)
                    else:
                        found_links.append(href)
        return found_links

if __name__ == '__main__':
    for a in ['google', 'altavista', 'yahoo', 'baidu', 'bing', 'webcrawler',
              'youdao', 'yandex']:
        dork = Dorker(a)
        res = dork.dork("lorea")
        print a,len(res)
        for b in res:
            print " *", b

