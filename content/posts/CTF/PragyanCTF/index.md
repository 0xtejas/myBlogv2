---
title: Franks Little Beauty
tags: 
    - Memory Forensics
    - Notedpad 
    - Deleted File
categories: 
    - "CTF Writeup"
date: 2022-03-07
description: "PragyanCTF'22 Memory Forensics Writeup"
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
    image: "https://user-images.githubusercontent.com/47889755/156966604-3c2b730c-9704-49f8-ad0b-b297846833de.png" # image path/url
    relative: false # when using page bundles set this to true
    hidden: false # only hide on current single page
---


## Description
Frank has never been a "tech person". He reuses passwords, is too lazy to type, the whole nine yards. And it's just not tech, he's blind as a bat and about as sharp as a round ball too. I mean, he doesn't even know about the shortcut to paddys. Help his son Dennis sift through this memory dump and reconstruct the flag
Note: Use the Win7SP1x64 profile to analyse the dump. All relevant files for this challenge are only present in the C drive and in no other drive
[Memory Dump](https://drive.google.com/file/d/1VPIdqIDFkOi3zGET2g00s1y-OeWOUqyi/view?usp=sharing)

## Writeup

First lets list the process and its tree

### Pslist

{{< figure src="images/pslist.png" >}}

### Pstree

{{< figure src="images/pstree.png" >}}

If you observe closely many notepad.exe were being executed.
To know what the user was doing with notepad let's check `cmdline`

### Cmdline

{{< figure src="images/cmdline.png" >}}

Okay, some files under Minesweeper directory was being edited.
Let's check if the user has something in clipboard. 

### Clipboard

{{< figure src="images/clipboard.png" >}}

so we have the following [link](https://pastebin.com/3Ecrm2DY)
Now we have the first part of the flag 1/3 `p_ctf{v0l4t1l1ty`

### Revisiting the Cmdline

In the screenshot there was a process which was used to extract file.
Let's get the rar file

### File Scan

{{< figure src="images/comp_rar_filescan.png" >}}

### Dump file and Extract Attempt

{{< figure src="images/dumpfiles_compRAR.png" >}}
{{< figure src="images/compRARExtractAttempt.png" >}}

It is password protected. 🤔 Hmm, yea description says the user is habitual to password reuse.
Let's dump is login password. NTLM Hashes

### Dump NTLM Hashes

{{< figure src="images/hashdump.png" >}}

Following hashes were dumped. Now let's crack it using [crackstation](https://crackstation.net/)
NTLM hash structure: `uid:rid:lmhash:nthash`
```txt
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Frank Reynolds:1000:aad3b435b51404eeaad3b435b51404ee:a88d1e18706d3aa676e01e5943d15911:::
HomeGroupUser$:1002:aad3b435b51404eeaad3b435b51404ee:af10ecac6ea817d2bb56e3e5c33ce1cd:::
Dennis:1003:aad3b435b51404eeaad3b435b51404ee:cf96684bbc7877920adaa9663698bf54:::
```
If you notice properly **LMHASH** begins with `aad3` which means it is empty. So we can use `NTHASH` to crack the password.
and now we found the password to be `trolltroll`


### Extracting RAR file
Let's extract the RAR compressed file. 

We now have part 2/3 of the flag.

{{< figure src="images/flag.png" >}}

### Revisiting the description
We are given with the clue **paddys**.
Let's do a file scan for paddys.

### File scan paddys
{{< figure src="images/paddys_filescan.png" >}}

### Dump file and analyze paddys.lnk
{{< figure src="images/analysing_paddys.png" >}}

If you have noticed it was lnk for sysinfo.txt, which we found earlier in cmdline.

### Dump sysinfo.txt 
{{< figure src="images/sysinfo_dump_attempt.png" >}}

Unfortuantely, memory is volatile. We can't say for sure which file resides on memory dump.
I assume it was deleted or not paged. Let's try to carve the file data from notepad's `memdump`
as mentioned by [andrea fortuna](https://andreafortuna.org/2018/03/02/volatility-tips-extract-text-typed-in-a-notepad-window-from-a-windows-memory-dump/)

### Memdump notepad.exe
Let's dump the process id 3016. Which was working on sysinfo.txt.
{{< figure src="images/flag3.png" >}}

Now we have the 3/3 of the flag.
Final flag: `p_ctf{v0l4t1l1ty_i5_v3ry_h4ndy_at_dump5_iasip}`
