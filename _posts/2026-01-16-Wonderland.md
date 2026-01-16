---
title: "TryHackMe: Wonderland"
date: 2026-01-16
categories: [TryHackMe]
tags: [Linux, Web]
published: true
---

Wonderland is a medium-difficulty ranked box on TryHackMe, it involves enumerating a webpage and good knowledge of linux privilege escalation to grab root access.

_Fall down the rabbit hole and enter wonderland._

## Scanning & Enumeration
Let’s kick it off with an Nmap scan on the given IP:

![](../assets/img/2026-01-16-Wonderland/1.png)

There’s only two services up and running on the system
- SSH on port 22
- A web server on port 80 written in Go

There aren’t any crazy exploits for OpenSSH 7.6p1 so let’s take a look around the webpage to find anything of use.

![](../assets/img/2026-01-16-Wonderland/2.png)

Not much here except a quote telling us to follow the rabbit. I run a directory search and find a few things of note. Of which is, an ‘/img’ directory with some standard photos for the site, a ‘/poem’ endpoint (pictured below), and something at ‘/r’.

![](../assets/img/2026-01-16-Wonderland/3.png)

I’m not sure if this is a red herring or may be of use later, but we’ll keep a note of it. The ‘/r’ directory leads to a ‘/a’, which tells me it’s spelling out something letter by letter. I throw together a quick script to find endpoints that contain one letter after it and get to ‘/r/a/b/b/i/t’.

![](../assets/img/2026-01-16-Wonderland/4.png)

It seems like it’s just more lines to the story on the page, until we look at the page source. There’s a hidden line containing SSH credentials for ‘alice’.

![](../assets/img/2026-01-16-Wonderland/5.png)

## Privilege Escalation
Safe to say we weren’t guessing that password! Now we can login and peek around the system, examining for ways to escalate privileges.

![](../assets/img/2026-01-16-Wonderland/6.png)

We only have access to alice’s home directory but are allowed to run sudo on ‘`walrus_and_the_carpenter.py`’. This script takes ten lines from the poem at random and outputs them to the terminal.

![](../assets/img/2026-01-16-Wonderland/7.png)

The file is unwritable so we can’t replace it with something malicious or create another script in its place.

_Note: “Everything is upside down here” is the hint, which is why the root.txt is in alice’s home directory and vice versa._

I run through the usual routes of PrivEsc, and I only find two capabilities set on Perl:

![](../assets/img/2026-01-16-Wonderland/8.png)

I’m neither root nor hatter so this is useless as of right now, we’ll revisit this later as [GTFOBins](https://gtfobins.github.io/) has a method for grabbing root shell via Perl.

When first trying to escalate to hatter’s account, I tried to leverage $PATH to create a new walrus_and_the_carpenter.py in /tmp and have that execute a reverse shell. However, this was overcomplicated and didn’t seem to work as I reread the original script and saw that the ‘random’ module was being imported.

![](../assets/img/2026-01-16-Wonderland/9.png)

We could simply create a script called random.py in our working directory and have that execute a command as rabbit.

![](../assets/img/2026-01-16-Wonderland/10.png)

I went with spawning a simple shell. Looking in the rabbit’s home directory, I find an ELF that outputs this:

![](../assets/img/2026-01-16-Wonderland/11.png)

It looks like there’s a date command being ran judging by the format. Let’s use this to make a lateral movement to hatter. First, I set /tmp as the first part of `$PATH` and make a file in /tmp that spawns a shell.

When we run the teaParty ELF, it will spawn a shell as hatter.

![](../assets/img/2026-01-16-Wonderland/12.png)

![](../assets/img/2026-01-16-Wonderland/13.png)

I find a password in hatter’s home directory and SSH with it for a better CLI. Now we can run the Perl script from earlier to escalate privileges to root and grab both flags.

![](../assets/img/2026-01-16-Wonderland/14.png)

![](../assets/img/2026-01-16-Wonderland/15.png)

This was a very fun box, I enjoyed the heavy focus on privilege escalation and the theme was great. Hope this was helpful if you’re following along with me and happy hacking!
