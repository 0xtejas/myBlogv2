---
title: Paper
tags: 
    - Wordpress
    - Easy
categories:
    - "Hack The Box Writeup"
date: 2022-02-09
description: "Hack The Box Machine - Paper writeup"
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
    image: "https://pbs.twimg.com/media/FKmnXsEXwAURwMy?format=jpg&name=medium" # image path/url
    relative: false # when using page bundles set this to true
    hidden: false # only hide on current single page
---

## Enumeration

### Port Scan

```bash
PORT    STATE SERVICE  REASON         VERSION
22/tcp  open  ssh      syn-ack ttl 63 OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   2048 10:05:ea:50:56:a6:00:cb:1c:9c:93:df:5f:83:e0:64 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDcZzzauRoUMdyj6UcbrSejflBMRBeAdjYb2Fkpkn55uduA3qShJ5SP33uotPwllc3wESbYzlB9bGJVjeGA2l+G99r24cqvAsqBl0bLStal3RiXtjI/ws1E3bHW1+U35bzlInU7AVC9HUW6IbAq+VNlbXLrzBCbIO+l3281i3Q4Y2pzpHm5OlM2mZQ8EGMrWxD4dPFFK0D4jCAKUMMcoro3Z/U7Wpdy+xmDfui3iu9UqAxlu4XcdYJr7Iijfkl62jTNFiltbym1AxcIpgyS2QX1xjFlXId7UrJOJo3c7a0F+B3XaBK5iQjpUfPmh7RLlt6CZklzBZ8wsmHakWpysfXN
|   256 58:8c:82:1c:c6:63:2a:83:87:5c:2f:2b:4f:4d:c3:79 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBE/Xwcq0Gc4YEeRtN3QLduvk/5lezmamLm9PNgrhWDyNfPwAXpHiu7H9urKOhtw9SghxtMM2vMIQAUh/RFYgrxg=
|   256 31:78:af:d1:3b:c4:2e:9d:60:4e:eb:5d:03:ec:a0:22 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKdmmhk1vKOrAmcXMPh0XRA5zbzUHt1JBbbWwQpI4pEX
80/tcp  open  http     syn-ack ttl 63 Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
|_http-title: HTTP Server Test Page powered by CentOS
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
| http-methods: 
|   Supported Methods: GET POST OPTIONS HEAD TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
443/tcp open  ssl/http syn-ack ttl 63 Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
|_http-title: HTTP Server Test Page powered by CentOS
| http-methods: 
|   Supported Methods: GET POST OPTIONS HEAD TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US/emailAddress=root@localhost.localdomain
```

## Sub Domain Enumeration

Found no subdomain using ffuf.

## Web Enumeration

### Directory Brute force

Foun no useful directory

### Nikto

Let’s try nikto as we didn’t find anything useful. 

{{< figure src="images/Untitled.png">}}

So now found a subdomain `paper.office`

### Wordpress

{{< figure src="images/Untitled%201.png">}}

Lets run wpscan with api key. why apikey? idk I had a very bad personal experience in a CTF, Using apikey showed the vulnerability in the CTF which I came to know after the event. So I prefer using API key from then.

<Screenshot of wpscan output missed>

I found lots of vulnerabilities 😳. Lets recon the website to narrow down what we need now.

{{< figure src="images/Untitled%202.png">}}

Now I need a way to disclose the *drafts.* Lets scroll the output of wpscan.

{{< figure src="images/Untitled%203.png">}}

### **CVE-2019-17671**

`?static=1` leaks the draft.

{{< figure src="images/Untitled%204.png">}}

## Enumeration in chat subdomain

{{< figure src="images/Untitled%205.png">}}

This is how it looks when we visit chat.office.paper. Now it says use the registration URL to register which we already have (we found it in private draft, check the previous screenshot).

After registering and logging in we have the following screen with some messages  for us in general channel.

{{< figure src="images/Untitled%206.png">}}

I’ve attached the following screenshot which is self explanatory. There is a bot with which we should try to interact with I guess.

{{< figure src="images/Untitled%207.png">}}

I’ll now create a new private channel and add the bot to interact with it. as the current channel is read only..

{{< figure src="images/Untitled%208.png">}}

I ran the command `recyclops help` to let it print the help menu and I noticed something interesting

{{< figure src="images/Untitled%209.png">}}

So 😈 I can read files in sales folder. Hmm 🤔 and list them to interesting lets see what the folder has.

### Messing with the bot

{{< figure src="images/Untitled%2010.png">}}

After messing around for some time, and proper enumeration I found the credentials in .env file I assumed password re-use and logged in as dwight with ssh. 

{{< figure src="images/Untitled%2011.png">}}

## Foothold

The credential is `dwight:Queenofblad3s!23`

{{< figure src="images/Untitled%2012.png">}}

Now we have Shell as user!

## Privilege Escalation

I ran linpeas and found it is vulnerable to a  CVE-2021-3560

{{< figure src="images/Untitled%2013.png">}}

### CVE-2021-3560

Time to exploit and get root.

{{< figure src="images/Untitled%2014.png">}}

After running several times as said its timing based script. I get the shell with new username 

{{< figure src="images/Untitled%2015.png">}}

{{< figure src="images/Untitled%2016.png">}}

rooted the box! 🎉