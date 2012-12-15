#!/usr/bin/python
# -*- coding: iso-8859-15 -*-
"""
Federated (full disclosure version) XSS pentesting.

Publish results on social networking sites. 
             
This implementation is for identi.ca (http://identi.ca)
and twitter (http://twitter.com/)

This bot is completly Public. All publised data will be accessed from Internet 

Please report your results using -automatic- format to create a good XSS pentesting Reporting Archive. 
Or try to create your own bot/s changing some configuration parameters and federate it (all as you want)
to this "2 first -replicants-: xsser-greyswarm" ;) 
								             
xsser-greyswarm: 
http://identi.ca/xsser-greyswarm

xsser-greyswarm(twitter clon): 
http://twitter.com/xsser-greyswarm

To launch you own -bot-, first create an account on identica/twitter, 
and after change this values with your data:

   - username = <identica username>
   - password = <identica password>

Dont forget to put your bot to "follow" other -replicants-.
If you dont know any, try this: xsserbot01

Happy "Cross" Federated Hacking. ;)
-----
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
import urllib2, urllib

class publisher(object):

    def __init__(self, xsser):
        # initialize main XSSer
        self.instance = xsser

    def send_to_identica(self, msg, username, password, url=None):
        if url is None:
            url = "http://identi.ca/api/statuses/update.xml"
        data = urllib.urlencode({'status':msg})
        passman = urllib2.HTTPPasswordMgrWithDefaultRealm()
        passman.add_password(None, url, username, password)
        authhandler = urllib2.HTTPBasicAuthHandler(passman)
        opener = urllib2.build_opener(authhandler)
        urllib2.install_opener(opener)
        pagehandle = urllib2.urlopen(url, data)
        print pagehandle

if __name__ == "__main__":
    publish = publisher(object)
    publish.send_to_identica('XSSer v1.6b -Grey Swarm!- Website: http://xsser.sf.net', 'xsserbot01', '8vnVw8wvs', 'http://identi.ca/api/statuses/update.xml')

