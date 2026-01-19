---
title: "TryHackMe: Different CTF"
date: 2026-01-18
categories: [TryHackMe]
tags: [Linux, Web, Cryptography, Brute Force]
published: true
---

This box is rated hard difficulty on THM. It involves us brute forcing steganography on an image using a wordlist found with it, uploading a shell via FTP & enumerating a subdomain to execute it. Finally, we brute force a user's password and exploit a custom binary which gives us root credentials hidden inside of a jpeg pulled from it.

_interesting room, you can shoot the sun_

## Scanning & Enumeration
Let's kick things off with an Nmap scan to find all running services for the given IP. I scan common UDP ports as well but get nothing returned.

![](../assets/img/2026-01-18-DifferentCTF/.png)

We see just two ports open:
- FTP on port 21
- HTTP on port 80

This vsftpd version is not prone to anything other than a DoS attack so I'll focus on the web server. Before heading over there I leave a directory and subdomain search running in the background to save on time.

![](../assets/img/2026-01-18-DifferentCTF/.png)

We already know it's Wordpress so WPScan will be of great help here to enumerate users and vulnerable plugins/themes. I also get redirected towards adana.thm so I add that to my /etc/hosts file.

There looks to be an 'announcements' directory exposed to us, inside is a wordlist of what looks like passwords as well as an ant.jpg. I use wget to download both files and start enumerating the WP site.

![](../assets/img/2026-01-18-DifferentCTF/.png)

```
$ wpscan --url http://adana.thm/ -e u,vp,vt
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
                               
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] Updating the Database ...
[i] Update completed.

[+] URL: http://adana.thm/ [10.64.143.231]
[+] Started: Sun Jan 18 19:02:17 2026

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://adana.thm/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://adana.thm/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://adana.thm/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.6 identified (Insecure, released on 2020-12-08).
 | Found By: Rss Generator (Passive Detection)
 |  - http://adana.thm/index.php/feed/, <generator>https://wordpress.org/?v=5.6</generator>
 |  - http://adana.thm/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.6</generator>

[+] WordPress theme in use: twentynineteen
 | Location: http://adana.thm/wp-content/themes/twentynineteen/
 | Last Updated: 2025-12-03T00:00:00.000Z
 | Readme: http://adana.thm/wp-content/themes/twentynineteen/readme.txt
 | [!] The version is out of date, the latest version is 3.2
 | Style URL: http://adana.thm/wp-content/themes/twentynineteen/style.css?ver=1.8
 | Style Name: Twenty Nineteen
 | Style URI: https://wordpress.org/themes/twentynineteen/
 | Description: Our 2019 default theme is designed to show off the power of the block editor. It features custom sty...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.8 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://adana.thm/wp-content/themes/twentynineteen/style.css?ver=1.8, Match: 'Version: 1.8'

[+] Enumerating Vulnerable Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Vulnerable Themes (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:00:06 <================================================> (652 / 652) 100.00% Time: 00:00:06
[+] Checking Theme Versions (via Passive and Aggressive Methods)

[i] No themes Found.

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <==================================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] hakanbey01
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://adana.thm/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sun Jan 18 19:02:29 2026
[+] Requests Done: 721
[+] Cached Requests: 8
[+] Data Sent: 181.381 KB
[+] Data Received: 23.345 MB
[+] Memory used: 286.676 MB
[+] Elapsed time: 00:00:12
```

WPScan gives us a single user by the name of 'hakanbey01' and also shows that XML-RPC is enabled which may let us brute force a login with it. I'll use the wordlist we found earlier and hopefully we get a login for them.

That returned nothing so I turned to Stegcracker to extract hidden data on the ant.jpg using the same wordlist.

![](../assets/img/2026-01-18-DifferentCTF/.png)

One of the last passwords works and we get base64 encoded creds for FTP. Let's login and have a look around.

![](../assets/img/2026-01-18-DifferentCTF/.png)

Awesome, we struck gold here! This seems to be the website's content folder which will let us read files and grab hakan's password. I also try to upload a PHP shell here in the wp-includes folder which is publicly facing but it doesn't update the site.

I end up downloading the wp-config.php file and find credentials for the phpmyadmin page.

![](../assets/img/2026-01-18-DifferentCTF/.png)

Once logged in, we have a few options to grab a shell. [This](https://medium.com/@toon.commander/uploading-a-shell-in-phpmyadmin-61b066b481a7) is an article about how we can use SQL to write into a file and execute it from our browser.

However, I find a subdomain for adana.thm which is actually the site we were uploading to on the FTP server.

_Realistically, my subdomain search at the beginning should've picked this up so I'll have to debug that later._

![](../assets/img/2026-01-18-DifferentCTF/.png)

## Initial Foothold
Adding that to my /etc/hosts file let me navigate to the shell.php I uploaded earlier. I made sure to `chmod 777 shell.php` and execute it via firefox. Now we have a low priv shell on the box.

Here we can grab the web flag under /var/www/html/ and start looking for ways to switch users to hakanbey. 

![](../assets/img/2026-01-18-DifferentCTF/.png)

We don't have access to much at all with our current permissions. In fact the find binary is disabled so I'll have to enumerate manually. There were no creds in the website's config files or /var/backups and seeing as we don't have access to any binaries or SSH, I resort to using [sucrack](https://github.com/ascemama/tools/blob/master/local/sucrack) to brute force hakanbey's account password.

```
./sucrack -u hakanbey wordlist.txt -w 50
```

Note: Use the `-w` flag to add threads as this could take a while.

After uploading both sucrack and the wordlist from /announcements/ to /tmp, I get nothing. I thought back to all the other passwords and noticed they all contain 123adana at the beginning, so I prepend that string to all lines in the list and rerun sucrack.

![](../assets/img/2026-01-18-DifferentCTF/.png)

This grants us his password and we can switch users to start looking for routes to gain root privileges.

![](../assets/img/2026-01-18-DifferentCTF/.png)

## Privilege Escalation
We can grab the user flag under hakan's home directory at this point. I come across an interesting binary owned by root when searching for files with an SUID bit set. 

![](../assets/img/2026-01-18-DifferentCTF/.png)

Running it prompts us to "enter the correct string". I was stuck for a bit here until realizing we can just use `ltrace` to discover calls to any shared libraries it may be using.

This outputs a `strcat()` function which gives us a few strings to use as the binary answer. Doing so copies a root.jpg file to our home directory and we can start finding ways to extract the hidden data.

![](../assets/img/2026-01-18-DifferentCTF/.png)

I transfer the .jpg to my local machine for more access to more tools. At this point I tried using exiftool, steghide, strings, etc. Opening the image just displayed the box's cover photo but I figured there had to be some data encrypted inside of it.

Looking back at the binary output, there's a hint saying "Hexeditor 00000020 => ????". After a while of messing around with it in CyberChef, I find the correct recipe is: `From Hex -> To Base 85`

![](../assets/img/2026-01-18-DifferentCTF/.png)

Decoding the third hex row in root.jpg grants us the credentials for root user. Only thing left is to sign in and grab the final flag to complete the box. 

![](../assets/img/2026-01-18-DifferentCTF/.png)

![](../assets/img/2026-01-18-DifferentCTF/.png)

Overall, this was a unique box; I hardly use sucrack because system passwords are usually hard to brute force (as seen here) and the custom binary was a nice touch. I hope this was helpful to anyone following along or stuck like I was and happy hacking!
