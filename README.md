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
     [Sucuri]: SucuriWAF 
     [Chrome]: Google Chrome
     [IE]: Internet Explorer
     [FF]: Mozilla's Gecko rendering engine, used by Firefox/Iceweasel
     [NS-IE]: Netscape in IE rendering engine mode
     [NS-G]: Netscape in the Gecko rendering engine mode
     [Opera]: Opera Browser

  ![XSSer](https://xsser.03c8.net/xsser/url_generation.png "XSSer URL Generation Schema")

----------

#### Installing:

XSSer runs on many platforms. It requires Python (3.x) and the following libraries:

    - python3-pycurl - Python bindings to libcurl (Python 3)
    - python3-bs4 - error-tolerant HTML parser for Python 3
    - python3-geoip - Python3 bindings for the GeoIP IP-to-country resolver library
    - python3-gi - Python 3 bindings for gobject-introspection libraries
    - python3-cairocffi - cffi-based cairo bindings for Python (Python3)
    - python3-selenium - Python3 bindings for Selenium
    - firefoxdriver - Firefox WebDriver support

On Debian-based systems (ex: Ubuntu), run: 

    sudo apt-get install python3-pycurl python3-bs4 python3-geoip python3-gi python3-cairocffi python3-selenium firefoxdriver

On other systems such as: Kali, Ubuntu, ArchLinux, ParrotSec, Fedora, etc... also run:

    sudo pip3 install pycurl bs4 pygeoip gobject cairocffi selenium

####  Source libs:

   * Python: https://www.python.org/downloads/
   * PyCurl: http://pycurl.sourceforge.net/
   * PyBeautifulSoup4: https://pypi.org/project/beautifulsoup4/
   * PyGeoIP: https://pypi.org/project/pygeoip/
   * PyGObject: https://pypi.org/project/gobject/
   * PyCairocffi: https://pypi.org/project/cairocffi/
   * PySelenium: https://pypi.org/project/selenium/

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

  ![XSSer](https://xsser.03c8.net/xsser/thehive6.png "XSSer [HTTP GET] [LOCAL] Reverse Exploit")

  ![XSSer](https://xsser.03c8.net/xsser/thehive7.png "XSSer [HTTP POST] [REMOTE] Reverse Exploit")

  ![XSSer](https://xsser.03c8.net/xsser/thehive8.png "XSSer [HTTP DOM] Exploit")

  ![XSSer](https://xsser.03c8.net/xsser/zika4.png "XSSer GeoMap")

