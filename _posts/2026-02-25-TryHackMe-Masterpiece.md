---
title: "TryHackMe: Masterpiece"
date: 2026-02-25
categories: [TryHackMe]
tags: [Linux, Web, Cookies, Python, Privilege Escalation, BinEx]
published: true
---

## Overview

This box simulates a curated online gallery where players explore a collection of artworks. The primary objective is to uncover hidden secrets and escalate privileges, ultimately retrieving both the user and root flags. The environment is built on Ubuntu, with a Flask web application, MySQL, Nginx, and a few custom binaries designed to hopefully create semi-realistic privilege escalation paths.

## Initial Access

Players begin by visiting the public website. The registration page allows the creation of a standard user account, granting limited access to the site. This account provides a session cookie that becomes essential later in the workflow. The site contains multiple tabs, including Home, About, History, and Gallery, while certain sections like uploads remain restricted until the player escalates privileges. Paying attention to the session management and cookies is critical in this stage.

## Exploring the Gallery

The Gallery section displays multiple artworks, each accompanied by a description and image. Each piece links to a “view metadata” page, which introduces a controlled Local File Inclusion (LFI) vulnerability. Only Python files or the main application source can be read through this LFI, allowing players to uncover the Flask signing secret. Metadata files are present to provide context and realism, but only the correct files lead toward privilege escalation.

## Forging an Admin Cookie

With the Flask signing secret obtained from the LFI, players can forge a session cookie with admin privileges. Once this admin cookie is used, the previously hidden Uploads tab becomes visible. This step teaches the importance of web application session management and cookie signing security, while providing a practical exploitation scenario in a contained environment.

## Uploading a Restoration Script

Admin users can access the Restoration Upload Portal to upload Python scripts that simulate artwork restoration tools. The box is configured so that these uploaded scripts are executed asynchronously, allowing players to spawn a reverse shell as the www-data user. This demonstrates remote code execution in a safe and realistic context, bridging the gap between web exploitation and local access.

## Pivoting to archivist

After gaining initial access via the web server, players can escalate to a local user named archivist. Hidden backup credentials for a MySQL database, stored in /opt/.secret/.backup_cred, allow players to dump database information and continue the escalation path. Exploring home directories and checking logs helps reveal subtle hints for the next step in the workflow.

## Privilege Escalation – Root Access

The box includes a custom SUID binary called frame_restore, owned by root. This binary is vulnerable to path injection, requiring players to manipulate the system path to execute a custom binary as root. Logs and realistic messages provide feedback without revealing the exploit outright, giving players an authentic Linux privilege escalation challenge.

## Flags

The user flag is located in archivist’s home directory and is tied to the initial pivot from www-data. The root flag is located in /root and is retrievable after exploiting the SUID binary. Both flags include thematic ASCII art to enhance immersion and tie the gameplay to the museum narrative.

## Learning Outcomes

Players practicing this box will gain experience in web application exploitation, including Flask cookie signing and LFI, as well as remote code execution through a controlled upload portal. They also practice local privilege escalation via MySQL credential reuse and SUID binary exploitation. Additionally, the box reinforces general security awareness, such as reading logs, following a structured workflow, and navigating Linux file permissions.
