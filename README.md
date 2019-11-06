  ![XSSer](https://xsser.03c8.net/xsser/thehive1.png "XSSer")

----------

 + Web: https://xsser.03c8.net

----------

  Cross Site "Scripter" (aka XSSer) is an automatic -framework- to detect, exploit and report XSS vulnerabilities in web-based applications.

  It provides several options to try to bypass certain filters and various special techniques for code injection.

  XSSer has pre-installed [ > 1300 XSS ] attacking vectors and can bypass-exploit code on several browsers/WAFs:

     [PHPIDS]: PHP-IDS
     [Imperva]: Imperva Incapsula WAF
     [WebKnight]: WebKnight WAF
     [F5]: F5 Big IP WAF
     [Barracuda]: Barracuda WAF
     [ModSec]: Mod-Security
     [QuickDF]: QuickDefense
     [Chrome]: Google Chrome
     [IE]: Internet Explorer
     [FF]: Mozilla's Gecko rendering engine, used by Firefox/Iceweasel
     [NS-IE]: Netscape in IE rendering engine mode
     [NS-G]: Netscape in the Gecko rendering engine mode
     [Opera]: Opera 

  ![XSSer](https://xsser.03c8.net/xsser/url_generation.png "XSSer URL Generation Schema")

----------

#### Installing:

  XSSer runs on many platforms. It requires Python and the following libraries:

      python-pycurl - Python bindings to libcurl
      python-xmlbuilder - create xml/(x)html files - Python 2.x
      python-beautifulsoup - error-tolerant HTML parser for Python
      python-geoip - Python bindings for the GeoIP IP-to-country resolver library

  On Debian-based systems (ex: Ubuntu), run: 

      sudo apt-get install python-pycurl python-xmlbuilder python-bs4 python-geoip

  On other systems such as: Kali, Ubuntu, ArchLinux, ParrotSec, Fedora, etc... also run:

      pip install geoip 

####  Source libs:

   * Python: https://www.python.org/downloads/
   * PyCurl: http://pycurl.sourceforge.net/
   * PyBeautifulSoup: https://pypi.python.org/pypi/BeautifulSoup
   * PyGeoIP: https://pypi.python.org/pypi/GeoIP

----------

####  License:

  XSSer is released under the GPLv3. You can find the full license text
in the [LICENSE](./docs/LICENSE) file.

----------

####  Screenshots:

  ![XSSer](https://xsser.03c8.net/xsser/thehive2.png "XSSer Shell")

  ![XSSer](https://xsser.03c8.net/xsser/thehive3.png "XSSer Manifesto")

  ![XSSer](https://xsser.03c8.net/xsser/thehive4.png "XSSer Configuration")

  ![XSSer](https://xsser.03c8.net/xsser/thehive5.png "XSSer Bypassers")

  ![XSSer](https://xsser.03c8.net/xsser/zika4.png "XSSer GeoMap")

