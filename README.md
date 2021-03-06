# UBNT EdgeMax dnsmasq Blacklist and Adware Blocking

[Click to view the https://community.ubnt.com/ thread](https://community.ubnt.com/t5/EdgeMAX/CLI-Integrated-dnsmasq-Adblocking-amp-Blacklisting-v3-7-6-Easy/td-p/1344740)

NOTE: THIS IS NOT OFFICIAL UBIQUITI SOFTWARE AND THEREFORE NOT SUPPORTED OR ENDORSED BY Ubiquiti Networks, Inc.

## **IMPORTANT**

***We do not plan to add new features to this package in the future, as it is in the maintenance mode only.***

In 2017 we created a new project, [blacklist](https://github.com/britannic/blacklist) written in Go, all development work is now focused [there](https://github.com/britannic/blacklist). Support for the new project can be found by reading and posting to this [Ubiquiti Community thread](https://community.ui.com/questions/DNS-Adblocking-and-Blacklisting-dnsmasq-Configuration-Integration-Package-v1-2-4-2/eb05f1b2-5316-4a80-8221-5e8b02575da4).

## Copyright

* Copyright (C) 2020 Helm Rock Consulting

## Overview

EdgeMax dnsmasq Blacklist and Adware Blocking is derived from the received wisdom found at [community.ubnt.com](https://community.ubnt.com/t5/EdgeMAX/bd-p/EdgeMAX)

## Licenses

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at

* http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

## Features

* Generates configuration files used directly by dnsmasq to redirect dns lookups
* Integrated with the EdgeMax OS CLI
* Any FQDN in the blacklist will force dnsmasq to return the configured dns redirect IP address

## Compatibility

* update-dnsmasq.pl has been tested on the EdgeRouter Lite and ER-X family of routers, versions v1.7.0-v1.9.7+hotfix.4
* Since the EdgeOS is a fork and port of Vyatta 6.3, this script could be adapted to work on VyOS and Vyatta derived ports

## Installation

* To install:
  * curl https://community.ubnt.com/ubnt/attachments/ubnt/EdgeMAX/78132/74/install_dnsmasq_blklist.v3.7.8.tgz | tar zvx
  * bash ./install_dnsmasq_blklist.v3.7.8
  * select menu option #0 if installing for the first time
  * select menu option #1 to remove the integration
    * if you have a previous version, run install again and select option #0

* Uninstall

  * /tmp/install_dnsmasq_blklist.v3.7.8
    * select option #1

---

## Version Release Notes

### v3.7.8

* Patch
  * Changed HTTP user agent to emulate curl, so that web servers won't attempt to set cookies etc.

### v3.7.7

* Patch
  * Fixed a bug in node.def to ensure config.boot blacklist nodes are correctly loaded during reboot.

### v3.7.6

* Patch
  * Fixes bug when CloudFlare or HTTP server returns an error page for a downloaded source. If the requested source page is proxied or returns a complex error, all the content was written to the dnsmasq source configuration file as a comment, but in some cases the commenting failed, due to xml or other types of output.

### v3.7.5

* Patch
  * Changed test routines to resolve IP lookups with dnsmasq, bypassing the router's internet DNS lookups
  * Simplified setup to use update-dnsmasq.pl and remove code redundancy
  * Tested on ER-X v1.9.7.hotfix.4
  * Tested on USG UniFi Gateway 3 v4.4.12
  * Tested on EdgeRouter Lite v1.9.7+hotfix.4

---

### v3.7.3

* Patch
  * Added a generic delete for the now unsupported Debian Wheezy-Backports repository
  * Tested on the ER-X with EdgeOS 1.9.7.hotfix.4

---

### v3.7.2

* Patch
  * Added a delete for the now unsupported Debian Wheezy-Backports repository
  * Add apt-utils download to ensure new TLS/SSL Perl libs are installed
  * Tested on the ER-X with EdgeOS 1.9.7.hotfix.4

---

### v3.7.1

* Patch
  * Removed Debian Wheezy-Backports repository
  * Added dropbox.com blacklist exclusions as some blocklists were false flagging it

---

### v3.7.0

* Updates
  * Added code to update HTTP::Tiny Perl library
  * Updated get_url() to verify SSL/TLS certificates

---

### v3.6.5

* Enhancements
  * Updated to set directory group ownership for /opt/vyatta/config to prevent issues  attempting commits as the admin user (factory default admin user is ubnt). Group ownership should be vyattacfg
  * Improved menu driven install
  * Added /config/postconfig.d/Install_dnsmasq_blklist
  * Added logic to prevent downloading from web sources with invalid SSL certificates

---

### v3.6.4.2

* Enhancements and minor bug fix
  * Added experimental support for UniFi Security Gateways (vv4.3.49 and above)
  * Fixed a minor vdisplay bug when running "update-dnsmasq.pl -version"

---

### v3.6.4.1

* Fix
  * Added back YoYo source as it is back online

---

### v3.6.4

* Fixes
  * Removed YoYo source as it is no longer active
  * Tested with EdgeOS v1.9.7+hotfix.4

---

### v3.6.3.3

* Enhancements
  * Additional exclusions added to the blacklist commands file

---

### v3.6.3.2

* Fixes
  * Rewrote vchecker to handle EdgeOS versions with an additional sub releases, i.e. v1.9.1.1, v1.9.1.1.1, etc
  * Added additional logic to skip testing if main installer exited with an error

---

### v3.6.3.1

* Fixes
  * Updated blacklist exclusions and includes
  * Removed volkerschatz as a source, since the blacklisting service is no longer offered

---

### v3.6

* Enhancements
  * Ability to add a source that uses a local file instead of HTTP

            set service dns forwarding blacklist hosts source myhosts description 'Blacklist file source'
            set service dns forwarding blacklist hosts source myhosts dns-redirect-ip 10.10.10.1
            set service dns forwarding blacklist hosts source myhosts file /config/user-data/blist.hosts.src

  * file contents example for /config/user-data/blist.hosts.src:

            gsmtop.net
            click.buzzcity.net
            ads.admoda.com
            stats.pflexads.com
            a.glcdn.co
            wwww.adleads.com
            ad.madvertise.de
            apps.buzzcity.net
            ads.mobgold.com
            android.bcfads.com
            req.appads.com
            show.buzzcity.net
            api.analytics.omgpop.com
            r.edge.inmobicdn.net
            www.mmnetwork.mobi
            img.ads.huntmad.com
            creative1cdn.mobfox.com
            admicro2.vcmedia.vn
            admicro1.vcmedia.vn

* Each source can now have its own dns-redirect-ip for granular control
        set service dns forwarding blacklist hosts source openphish dns-redirect-ip 172.16.10.1

* Revised source list
  * Redundant sources removed:
            delete service dns forwarding blacklist hosts source adaway # description 'Blocking mobile ad providers and some analytics providers'
            delete service dns forwarding blacklist hosts source malwaredomainlist # description '127.0.0.1 based host and domain list'
            delete service dns forwarding blacklist hosts source someonewhocares # description 'Zero based host and domain list'
            delete service dns forwarding blacklist hosts source winhelp2002 # description 'Zero based host and domain list'

  * Retained sources:
            set service dns forwarding blacklist domains source malc0de description 'List of zones serving malicious executables observed by malc0de.com/database/'
            set service dns forwarding blacklist domains source malc0de prefix 'zone '
            set service dns forwarding blacklist domains source malc0de url 'http://malc0de.com/bl/ZONES'
            set service dns forwarding blacklist hosts source openphish description 'OpenPhish automatic phishing detection'
            set service dns forwarding blacklist hosts source openphish prefix http
            set service dns forwarding blacklist hosts source openphish url 'https://openphish.com/feed.txt'
            set service dns forwarding blacklist hosts source volkerschatz description 'Ad server blacklists'
            set service dns forwarding blacklist hosts source volkerschatz prefix http
            set service dns forwarding blacklist hosts source volkerschatz url 'http://www.volkerschatz.com/net/adpaths'
            set service dns forwarding blacklist hosts source yoyo description 'Fully Qualified Domain Names only - no prefix to strip'
            set service dns forwarding blacklist hosts source yoyo prefix ''
            set service dns forwarding blacklist hosts source yoyo url 'http://pgl.yoyo.org/as/serverlist.php?hostformat=nohtml&showintro=1&mimetype=plaintext'

  * Added sources:
    * Domains:
                set service dns forwarding blacklist domains source simple_tracking description 'Basic tracking list by Disconnect'
                set service dns forwarding blacklist domains source simple_tracking prefix ''
                set service dns forwarding blacklist domains source simple_tracking url 'https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt'
                set service dns forwarding blacklist domains source zeus description 'abuse.ch ZeuS domain blocklist'
                set service dns forwarding blacklist domains source zeus prefix ''
                set service dns forwarding blacklist domains source zeus url 'https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist'
  * Hosts:
                set service dns forwarding blacklist hosts source raw.github.com description 'This hosts file is a merged collection of hosts from reputable sources'
                set service dns forwarding blacklist hosts source raw.github.com prefix '0.0.0.0 '
                set service dns forwarding blacklist hosts source raw.github.com url 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts'
                set service dns forwarding blacklist hosts source sysctl.org description 'This hosts file is a merged collection of hosts from cameleon'
                set service dns forwarding blacklist hosts source sysctl.org prefix '127.0.0.1	 '
                set service dns forwarding blacklist hosts source sysctl.org url 'http://sysctl.org/cameleon/hosts'

* Additional excludes added to blacklist configuration list

---

### v3.5.5

* Updates/fixes include:
  * Added clarifying explanation for failed IP tests; advises user to ignore if router resolves upstream DNS and not locally
  * Fixed minor bug with command shell redirection
  * Additional excludes added to blacklist configuration list

---

### v3.5.3

* Updates/fixes include:
  * Added code to fix 'set' failures if /opt/vyatta/active/service/dns/forwarding/ group ownership isn't writable for the operator
  * Additional excludes added based on user feedback
  * Minor optimizations and additional tests added
  * Setup commands now include PURGE to clean up stale config sessions

---

### v3.5

* Updates/fixes include:
  * Global exclude is now available ([set service dns forwarding blacklist exclude ...])
  * Removed --debug option from update-dnsmasq.pl
  * New validator script (/configure/scripts/blacklist.t) runs a battery of tests on the blacklist configuration to ensure it is working correctly or checks it is removed correctly
  * Setup/Remove scripts rewritten in Perl
  * Fixed issue with install that prevented admin user configuration
  * Installer now runs under admin and only uses sudo where absolutely necessary
  * Installer checks to see if service dns forwarding is configured and bails it if not with warning/example configuration
  * Installer includes these new options:
  * Non-essential functions have been pruned, command line switches reduced to:

---

### v3.3.2

* Non-essential functions have been removed
  * Command line switches reduced to:

            /config/scripts/update-dnsmasq.pl -h
            usage: update-dnsmasq.pl <options>
            options:
                --debug     # enable debug output
                -f <file>   # load a configuration file
                --help      # show help and usage text
                -v          # verbose output
                --version   # show program version number

  * Improved exclusion list rejection
  * Ability to create a domain list from a source that has FQDNs using the new 'compress' switch (note, use with caution, since you may find legit domains getting completely blocked - especially cloud services like amazonaws, in that case you will need to add specific excludes):

            set service dns forwarding blacklist domains source FQDNs_Source compress true

  * Install/remove scripts rewritten in Perl for better error checking
  * Install/remove logs will be written to /var/log for diagnostics
  * Flagged domain list with optional include commands written to /var/log/update-dnsmasq_flagged_domains.cmds
  * Each source will be written to its own file:

            root@ubnt:/etc/dnsmasq.d# ls
            README
            domains.malc0de.com.blacklist.conf
            domains.pre-configured.blacklist.conf
            hosts.adaway.blacklist.conf
            hosts.hpHosts.blacklist.conf
            hosts.pre-configured.blacklist.conf
            hosts.someonewhocares.org.blacklist.conf
            hosts.winhelp2002.mvps.org.blacklist.conf
            hosts.www.malwaredomainlist.com.blacklist.conf
            hosts.yoyo.org.blacklist.conf

  * Log file (/var/log/update-dnsmasq.pl) now flags frequently blacklisted domains, so you can optionally decide to add them as an include under domains:

            root@ubnt:/etc/dnsmasq.d# tail -n 30 /var/log/update-dnsmasq.log
            Nov 29 09:45:50 2015: INFO: hosts blacklisted: domain loniricarena.ru 4 times
            Nov 29 09:45:50 2015: INFO: hosts blacklisted: domain starwave.com 5 times
            Nov 29 09:45:50 2015: INFO: hosts blacklisted: domain axf8.net 41 times
            Nov 29 09:45:50 2015: INFO: hosts blacklisted: domain com-swd.net 4 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain jaimiehonoria.com 4 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain your-drug-blog.com 4 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain wileenallix.ru 5 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain com-5ny.net 4 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain bb.13900139000.com 4 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain in.th 6 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain adhese.com 5 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain gueneveredeane.com 4 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain xn--c1aqdux1a.xn 4 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain kathlingertrud.com 5 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain peqi.healthhuman.net 4 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain jessamineelvira.ru 9 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain xn--c1abhkul5co5f.xn 7 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain com-0to.net 6 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain 9458.302br.net 19 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain xn--80aasb3bf1bvw.xn 5 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain web.id 4 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain ap.org 4 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain webjump.com 4 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain blueseek.com 11 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain j595j4.com 4 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain axeynlzljpld.com 4 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain jemieandrea.com 59 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain llnwd.net 24 times
            Nov 29 09:45:51 2015: INFO: hosts blacklisted: domain thomasadot.com 4 times
            Nov 29 09:45:52 2015: INFO: Reloading dnsmasq configuration...

  * Improved memory usage for threads has been implemented
  * Uses HTTP::Tiny for smaller memory footprint with threads
  * Optional -f config.boot parser has been completely rewritten, so that the XorpConfigParser.pm module is no longer required (saves on memory overhead and compilation time)
  * Over 70% of the code has been rewritten or updated

---

### v3.24d

* Updates include:
  * 'hosts' exclusions now incorporates 'domains' exclusions and blacklists
  * Additional 'good hosts' excluded from blacklisting in the supplied install configuration
  * Fixes excluded FQDNs by using precise matching instead of fuzzy (i.e. 1.domain.tld won't also exclude b1.domain.tld)
  * Entire blacklist can be disabled using 'set service dns forwarding blacklist disabled true'
  * Ability to add domain sources, which compile to domain.blacklist.conf allowing for domain wildcards, so that all hosts in a domain will now be blocked
  * Exclude and include lists have been moved and now apply to their parent area, e.g. 'hosts' or 'domains'
  * New --disable switch enables ADBlock by setting [set service dns forwarding blacklist enabled false]
  * New --enable switch enables ADBlock by setting [set service dns forwarding blacklist enabled true]
  * Now uses multi-threading for simultaneous blacklist downloads
  * Revamped stream processor, now has ability to extract multiple FQDNs from each line or input
  * Useragent: HTTP get requests now include browser agent information to prevent website robot rejection
  * Useragent: HTTP/HTTPS handling uses useragent for improved error/timeout control
  * Uses own node.def to maintain configuration changes. This also forces the script to run the dnsmasq configuration update after DNS is up during boot time

---

### v3.22rc1

* Updates include:
  * Fixes excluded FQDNs by using precise matching instead of fuzzy (i.e. 1.domain.tld won't also exclude b1.domain.tld)
  * New --disable switch enables ADBlock by setting [set service dns forwarding blacklist enabled false]
  * New --doc switch prints out condensed man page
  * New --enable switch enables ADBlock by setting [set service dns forwarding blacklist enabled true]
  * Now uses multi-threading for simultaneous blacklist downloads
  * Revamped stream processor, now has ability to extract multiple FQDNs from each line or input
  * Useragent: HTTP get requests now include browser agent information to prevent website robot rejection
  * Useragent: HTTP/HTTPS handling uses useragent for improved error/timeout control
  * Uses own node.def to maintain configuration changes. This also forces the script to run the dnsmasq configuration update after DNS is up during router boot time

---

### v3.15

* Enhancements:
  * Logging to /var/log/update-blacklists-dnsmasq.log
  * --debug option: prints status messages
  * Additional download sources added to the default lists
  * Added retry logic for download sources that time out
  * Task scheduler update interval is now every 6 hours, as some of the sources change hourly (configure interval using "set system task-scheduler task update_blacklists interval"
  * Status line retains previous downloads for more detail

---

### v3.12

* Fixes:
  * Fixed bug reported by @soehest where certain FQDNs were being rejected by the stream processor.

---

### v3.10

* Enhancements:
  * Now supports https:// source URLs and improved regex handling in the stream processing engine.

---

### v3.00

* Enhancements:
  * No longer requires regex strings, just the line prefix/preamble before the hostname in the download. If a version of ADBlock was installed previously, you will need to select option 2 to remove it and then install this version. This is necessary to ensure the configure paths are correctly set up for the new prefix option which replaces the regex string.

---

## Post Installation

* Here is the scheduler configuration after running install_adblock:

```python
    show system task-scheduler
     task update_blacklists {
         executable {
             path /config/scripts/update-blacklists-dnsmasq.pl
         }
         interval 1d
     }
```

* The script will also install a default blacklist setup, here is the stanza (show service dns forwarding blacklist):

```json
blacklist {
    disabled false
    dns-redirect-ip 0.0.0.0
    domains {
        exclude adobedtm.com
        exclude apple.com
        exclude coremetrics.com
        exclude doubleclick.net
        exclude google.com
        exclude googleadservices.com
        exclude googleapis.com
        exclude hulu.com
        exclude msdn.com
        exclude paypal.com
        exclude storage.googleapis.com
        include adsrvr.org
        include adtechus.net
        include advertising.com
        include centade.com
        include doubleclick.net
        include free-counter.co.uk
        include kiosked.com
        source malc0de.com {
            description "List of zones serving malicious executables observed by malc0de.com/database/"
            prefix "zone "
            url http://malc0de.com/bl/ZONES
        }
    }
    hosts {
        exclude appleglobal.112.2o7.net
        exclude autolinkmaker.itunes.apple.com
        exclude cdn.visiblemeasures.com
        exclude freedns.afraid.org
        exclude hb.disney.go.com
        exclude static.chartbeat.com
        exclude survey.112.2o7.net
        exclude ads.hulu.com
        exclude ads-a-darwin.hulu.com
        exclude ads-v-darwin.hulu.com
        exclude track.hulu.com
        include beap.gemini.yahoo.com
        source openphish.com {
            description "OpenPhish automatic phishing detection"
            prefix http
            url https://openphish.com/feed.txt
        }
        source someonewhocares.org {
            description "Zero based host and domain list"
            prefix 0.0.0.0
            url http://someonewhocares.org/hosts/zero/
        }
        source volkerschatz.com {
            description "Ad server blacklists"
            prefix http
            url http://www.volkerschatz.com/net/adpaths
        }
        source winhelp2002.mvps.org {
            description "Zero based host and domain list"
            prefix "0.0.0.0 "
            url http://winhelp2002.mvps.org/hosts.txt
        }
        source www.malwaredomainlist.com {
            description "127.0.0.1 based host and domain list"
            prefix "127.0.0.1 "
            url http://www.malwaredomainlist.com/hostslist/hosts.txt
        }
        source yoyo.org {
            description "Fully Qualified Domain Names only - no prefix to strip"
            prefix ""
            url http://pgl.yoyo.org/as/serverlist.php
        }
    }
}
```

## Example CLI commands to configure the ADBlock Blacklist

```bash
set service dns forwarding blacklist dns-redirect-ip 0.0.0.0
set service dns forwarding blacklist disabled false
set service dns forwarding blacklist domains exclude adobedtm.com
set service dns forwarding blacklist domains exclude apple.com
set service dns forwarding blacklist domains exclude coremetrics.com
set service dns forwarding blacklist domains exclude doubleclick.net
set service dns forwarding blacklist domains exclude google.com
set service dns forwarding blacklist domains exclude googleadservices.com
set service dns forwarding blacklist domains exclude googleapis.com
set service dns forwarding blacklist domains exclude hulu.com
set service dns forwarding blacklist domains exclude msdn.com
set service dns forwarding blacklist domains exclude paypal.com
set service dns forwarding blacklist domains exclude storage.googleapis.com
set service dns forwarding blacklist domains include adsrvr.org
set service dns forwarding blacklist domains include adtechus.net
set service dns forwarding blacklist domains include advertising.com
set service dns forwarding blacklist domains include centade.com
set service dns forwarding blacklist domains include doubleclick.net
set service dns forwarding blacklist domains include free-counter.co.uk
set service dns forwarding blacklist domains include kiosked.com
set service dns forwarding blacklist domains source malc0de.com description 'List of zones serving malicious executables observed by malc0de.com/database/'
set service dns forwarding blacklist domains source malc0de.com prefix 'zone '
set service dns forwarding blacklist domains source malc0de.com url 'http://malc0de.com/bl/ZONES'
set service dns forwarding blacklist hosts exclude appleglobal.112.2o7.net
set service dns forwarding blacklist hosts exclude autolinkmaker.itunes.apple.com
set service dns forwarding blacklist hosts exclude cdn.visiblemeasures.com
set service dns forwarding blacklist hosts exclude freedns.afraid.org
set service dns forwarding blacklist hosts exclude hb.disney.go.com
set service dns forwarding blacklist hosts exclude ads.hulu.com
set service dns forwarding blacklist hosts exclude ads-a-darwin.hulu.com
set service dns forwarding blacklist hosts exclude ads-v-darwin.hulu.com
set service dns forwarding blacklist hosts exclude track.hulu.com
set service dns forwarding blacklist hosts exclude static.chartbeat.com
set service dns forwarding blacklist hosts exclude survey.112.2o7.net
set service dns forwarding blacklist hosts include beap.gemini.yahoo.com
set service dns forwarding blacklist hosts source openphish.com description 'OpenPhish automatic phishing detection'
set service dns forwarding blacklist hosts source openphish.com prefix http
set service dns forwarding blacklist hosts source openphish.com url 'https://openphish.com/feed.txt'
set service dns forwarding blacklist hosts source someonewhocares.org description 'Zero based host and domain list'
set service dns forwarding blacklist hosts source someonewhocares.org prefix 0.0.0.0
set service dns forwarding blacklist hosts source someonewhocares.org url 'http://someonewhocares.org/hosts/zero/'
set service dns forwarding blacklist hosts source volkerschatz.com description 'Ad server blacklists'
set service dns forwarding blacklist hosts source volkerschatz.com prefix http
set service dns forwarding blacklist hosts source volkerschatz.com url 'http://www.volkerschatz.com/net/adpaths'
set service dns forwarding blacklist hosts source winhelp2002.mvps.org description 'Zero based host and domain list'
set service dns forwarding blacklist hosts source winhelp2002.mvps.org prefix '0.0.0.0 '
set service dns forwarding blacklist hosts source winhelp2002.mvps.org url 'http://winhelp2002.mvps.org/hosts.txt'
set service dns forwarding blacklist hosts source www.malwaredomainlist.com description '127.0.0.1 based host and domain list'
set service dns forwarding blacklist hosts source www.malwaredomainlist.com prefix '127.0.0.1 '
set service dns forwarding blacklist hosts source www.malwaredomainlist.com url 'http://www.malwaredomainlist.com/hostslist/hosts.txt'
set service dns forwarding blacklist hosts source yoyo.org description 'Fully Qualified Domain Names only - no prefix to strip'
set service dns forwarding blacklist hosts source yoyo.org prefix ''
set service dns forwarding blacklist hosts source yoyo.org url 'http://pgl.yoyo.org/as/serverlist.php?hostformat=nohtml&showintro=1&mimetype=plaintext'
set system task-scheduler task update_blacklists executable path /config/scripts/update-dnsmasq.pl
set system task-scheduler task update_blacklists interval 1d
```

## Notes

For proper operation, first ensure dnsmasq is set up correctly, e.g.:

```bash
show service dns forwarding
cache-size 150
/* Set to WAN interface or specify "listen-on"" interfaces instead */
except-interface eth1
name-server 208.67.220.220
name-server 208.67.222.222
name-server 2620:0:ccc::2
name-server 2620:0:ccd::2
options expand-hosts
options bogus-priv
options localise-queries
options domain=ubnt.home
options strict-order
options listen-address=127.0.0.1
system
```