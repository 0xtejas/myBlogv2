---
title: Shibboleth
tags: 
    - CVE-2021-27928
    - MYSQL
    - Zabbix
    - "Medium Machines"
categories:
    - "Hack The Box Writeup"
date: 2022-01-11
description: "Hack The Box Machine - Shibboleth writeup"
author: "Tejas"
showToc: true
TocOpen: false
draft: false
hidemeta: false
comments: true
disableHLJS: false 
disableHLJS: false
hideSummary: true
searchHidden: false
ShowReadingTime: true
ShowBreadCrumbs: true
ShowPostNavLinks: true
ShowWordCount: true
ShowRssButtonInSectionTermList: false
UseHugoToc: true
cover:
    image: "https://pbs.twimg.com/media/FD1vLqBWUAEmB3b?format=jpg&name=4096x4096" # image path/url
    relative: false # when using page bundles set this to true
    hidden: false # only hide on current single page
---


## Enumeration

### Port Scanning

### TCP

```bash
# Nmap 7.92 scan initiated Fri Dec 10 01:33:54 2021 as: nmap -sC -sS -sV -oN nmap_full.txt -vvv -p- shibboleth.htb
Nmap scan report for shibboleth.htb (10.10.11.124)
Host is up, received echo-reply ttl 63 (0.051s latency).
Scanned at 2021-12-10 01:33:55 EST for 77s
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: FlexStart Bootstrap Template - Index
|_http-favicon: Unknown favicon MD5: FED84E16B6CCFE88EE7FFAAE5DFEFD34
|_http-server-header: Apache/2.4.41 (Ubuntu)

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Dec 10 01:35:12 2021 -- 1 IP address (1 host up) scanned in 78.00 seconds
```

### UDP

```bash
# Nmap 7.92 scan initiated Fri Dec 10 06:57:55 2021 as: nmap -sU -vvv -oN nmap_udp_full.txt --min-rate=2000/5000/10000 --open shibboleth.htb
Nmap scan report for shibboleth.htb (10.10.11.124)
Host is up, received echo-reply ttl 63 (0.048s latency).
Scanned at 2021-12-10 06:57:55 EST for 2s
Not shown: 7 closed udp ports (port-unreach)
PORT      STATE         SERVICE           REASON
2/udp     open|filtered compressnet       no-response
3/udp     open|filtered compressnet       no-response
                
------ snipped ------

623/udp   open          asf-rmcp          udp-response ttl 63
```

623 UDP port 🤔, what could `asf-rmcp` be?

Found some procedure guidelines in [book.hacktricks.xyz](https://book.hacktricks.xyz/pentesting/623-udp-ipmi) 

### Exploring UDP service

I shall enumerate the version using msfconsole. 

{{< figure src="images/Untitled.png">}}

So the service version is `2.0` and let's use metasploit's exploit for version 2.0 to retrieve the password hash as per the article

{{< figure src="images/Untitled%201.png">}}

```
Administrator:b9d2051f82050000d5874417c367dce08432bdb930d456f7e03084d5b66bd9ad50b799a7b397163ea123456789abcdefa123456789abcdef140d41646d696e6973747261746f72:38ef2b05ff9a60ab31c0383f3cb1386bd2d496c4
```

Cracked the hash

{{< figure src="images/Untitled%202.png">}}

`Administrator:ilovepumkinpie1`

## Web Enumeration

### Subdomain Enumeration

`ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u "http://shibboleth.htb/" -H "Host:FUZZ.shibboleth.htb" --fw 18`

{{< figure src="images/Untitled%203.png">}}

Found 3 sub-domains

1. monitor
2. monitoring
3. zabbix

### Directory Search

`feroxbuster -u http://shibboleth.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt`

No interesting directory found.

### Enumerating Zabbix

I found a interesting [scripts](https://github.com/freeworkaz/zabbix_test) for enumerating Zabbix in GitHub 

### Detecting version

I found a [script](https://raw.githubusercontent.com/freeworkaz/zabbix_test/master/zabbix_version_detect.py) for enumerating Zabbix version. And it detected it as **5.0**

{{< figure src="images/Untitled%204.png">}}

## Foothold

Let's break into Zabbix to gain a our foothold.

Logged in with the creds found from the UDP service 

{{< figure src="images/Untitled%205.png">}}

Zanbbix 5.0.17 is the version which is running

Go to `configuration > hosts > items > create item` 

I wrote the payload for reverse shell in `key`. 

{{< figure src="images/Untitled%206.png">}}

{{< figure src="images/Untitled%207.png">}}

I got a shell then lets su to `ipmi-svc` with the password we have. 

Got user

## Privilege Escalation

### Open Ports

{{< figure src="images/Untitled%208.png">}}

### Linpeas

Found Nothing interesting 

### Manual Enumeration

Found password for mysql db 

`grep -iR "password" /etc/ 2>/dev/null | uniq | sort`

{{< figure src="images/Untitled%209.png">}}

{{< figure src="images/Untitled%2010.png">}}

### MYSQL DB CREDS

`zabbix:bloooarskybluh`

### Command Injection - MARIADB

[CVE-2021-27928](https://packetstormsecurity.com/files/162177/MariaDB-10.2-Command-Execution.html) exploit can be found in this [repo](https://github.com/Al1ex/CVE-2021-27928)

{{< figure src="images/Untitled%2011.png">}}

Rooted the machine