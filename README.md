  ![XSSer](https://xsser.03c8.net/xsser/blackswarm_banner.png "XSSer v1.9 - Bl4ck Swarm!")

----------

 + Web: https://xsser.03c8.net

----------

  Cross Site "Scripter" (aka XSSer) is an automatic -framework- to detect, exploit and report XSS vulnerabilities in web-based applications.

  It provides several options to try to bypass certain filters and various special techniques for code injection.

  Key features:

     - [ > 1500 ] pre-installed XSS attacking vectors (automatic fuzzing).
     - Validation: each finding is verified for real executability. A context-aware engine tells apart executable contexts (HTML, JS, event handlers, javascript:/data: URIs) from harmless reflections, with an optional headless-browser reverse connection (--reverse-check) to confirm findings and cut false positives.
     - Targeting: URL, file, stdin/pipe, raw HTTP request (-r), 'dorking' (multiple engines) and crawler.
     - Injection: GET/POST, Cookie/User-Agent/Referer, DOM and HTTP Response Splitting.
     - Evasion: per-WAF bypassers + character-encoding bypassers; proxy/Tor; client-certificate auth.
     - Reporting: PDF (professional), XML and JSON (for CI / pipelines).

  It can also bypass-exploit code on several WAFs:

     [Cloudflare]: Cloudflare WAF
     [Akamai]: Akamai (Kona / App & API Protector)
     [AWS]: AWS WAF
     [Azure]: Azure Front Door WAF
     [Imperva]: Imperva (Incapsula / Cloud WAF)
     [F5]: F5 BIG-IP ASM / Advanced WAF
     [Barracuda]: Barracuda WAF
     [ModSec]: Mod-Security + OWASP CRS v3
     [Wordfence]: Wordfence (WordPress)
     [Sucuri]: Sucuri (CloudProxy)
     [FortiWeb]: Fortinet FortiWeb
     [WebKnight]: AQTRONIX WebKnight

  ![XSSer](https://xsser.03c8.net/xsser/blackswarm_options.png "XSSer v1.9 - WAF Bypassers & Encoders")

----------

#### Installing:

XSSer runs on many platforms. It requires Python (>=3.9).

Only two libraries are mandatory (the core HTTP engine and the HTML parser):

    - pycurl        - Python bindings to libcurl
    - beautifulsoup4 - error-tolerant HTML parser

The rest are optional and only needed for a specific feature. If missing, XSSer
can auto-install them on demand (pip) the first time the feature is used, except
on 'externally-managed' (PEP 668) Python environments, where it prints the manual
install command instead (set XSSER_AUTOINSTALL=1 to override):

    - fpdf2         - '--pdf' report exporter                    [extra: pdf]
    - ddgs          - 'dorking' engine ('-d' / '-l')            [extra: dork]
    - selenium      - DOM / reverse-check browser ('--Dom')      [extra: dom]
    - PyGObject + pycairo + pygeoip + Pillow - GTK GUI + GeoMap ('--gtk')  [extra: gtk]

Install (from the source tree), core only or with the extras you want:

    pip3 install .                 # mandatory libs only
    pip3 install .[pdf]            # + PDF reporting
    pip3 install .[full]          # everything (all optional features)

On Debian-based systems (ex: Kali, Ubuntu, ParrotSec) the same libs are also
packaged. The distro package name differs from the pip name; the mapping is:

    pip name        Debian/Ubuntu/Kali package
    ------------    --------------------------
    beautifulsoup4  python3-bs4
    pycurl          python3-pycurl
    fpdf2           python3-fpdf2
    selenium        python3-selenium
    PyGObject       python3-gi
    pycairo         python3-cairo   (+ python3-gi-cairo for GTK integration)
    Pillow          python3-pil
    pygeoip         python3-geoip
    (ddgs has no distro package yet: install it with pip)

    # mandatory:
    sudo apt-get install python3-pycurl python3-bs4
    # optional (per feature you want to enable):
    sudo apt-get install python3-fpdf2 python3-selenium python3-gi python3-gi-cairo python3-cairo python3-pil python3-geoip

Note: some optional features also need system-level (non-pip) components:

    - '--Dom' / '--reverse-check' : firefox + geckodriver (the Firefox WebDriver).
    - '--gtk'                     : GTK 3 plus its GObject-Introspection typelib
                                    files (the .typelib for Gtk-3.0). That typelib
                                    ships under different system package names per
                                    distro, e.g. 'gir1.2-gtk-3.0' on Debian/Ubuntu/
                                    Kali, and 'gtk3' on Fedora/Arch.

####  Source libs:

   * Python: https://www.python.org/downloads/
   * PyCurl: https://pypi.org/project/pycurl/
   * BeautifulSoup4: https://pypi.org/project/beautifulsoup4/
   * fpdf2: https://pypi.org/project/fpdf2/
   * ddgs: https://pypi.org/project/ddgs/
   * Selenium: https://pypi.org/project/selenium/
   * PyGObject: https://pypi.org/project/PyGObject/
   * pycairo: https://pypi.org/project/pycairo/
   * PyGeoIP: https://pypi.org/project/pygeoip/
   * Pillow: https://pypi.org/project/Pillow/

----------

####  License:

  XSSer is released under the GPLv3. You can find the full license text
in the [COPYING](doc/COPYING) file.

----------

####  Screenshots:

  ![XSSer](https://xsser.03c8.net/xsser/blackswarm_shell.png "XSSer Shell")

  ![XSSer](https://xsser.03c8.net/xsser/blackswarm_dorking.png "XSSer Dorking (multiple engines)")

  ![XSSer](https://xsser.03c8.net/xsser/blackswarm_gui.png "XSSer GTK GUI")

  ![XSSer](https://xsser.03c8.net/xsser/blackswarm_gui_waf.png "XSSer GUI - Anti-antiXSS/IDS WAF Bypassers")

  ![XSSer](https://xsser.03c8.net/xsser/blackswarm_gui_bypasser.png "XSSer GUI - Encoders & Bypassers")

  ![XSSer](https://xsser.03c8.net/xsser/blackswarm_report.png "XSSer PDF Report")
  
  ![XSSer](https://xsser.03c8.net/xsser/blackswarm_map.png "XSSer GeoMap")

