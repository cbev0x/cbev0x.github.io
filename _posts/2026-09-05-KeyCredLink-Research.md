---
title: "Trust Me, I Did MFA"
date: 2026-09-05
categories: [Personal, Research]
tags: [Windows, Active Directory, Cryptography, MFA, Research]
published: true
---

Most of my time goes into how the Windows KDC decides who you get to be and what ends up in your PAC. This one started with a smaller question that had been bugging me for a while, which is that when Windows tells the rest of the domain a logon was backed by MFA, it has to learn that fact from somewhere, and I wanted to know where. It turns out the answer is an attribute you can write to yourself.

The short version is that the KDC will vouch for your key having done multi-factor auth, or for it living inside a TPM, based on nothing more than a flag the key's owner sets, and it never checks whether either thing is actually true. I'll cover the attribute first, then the abuse everyone already knows about, and then the part I found.

## What msDS-KeyCredentialLink holds

Windows Hello for Business needs somewhere to keep your public key, and that somewhere is `msDS-KeyCredentialLink` on your account object. When you enroll, the device generates an asymmetric key pair and keeps the private half locally, ideally sealed inside the TPM, while the public half gets written into that attribute, which is multi-valued so a single account can carry several keys at once.

At sign-in the client runs PKINIT, signing a request with the private key and presenting the matching public key, and the KDC walks your `msDS-KeyCredentialLink` values until it finds one that matches and hands back a TGT. That flow is called key trust, and there is no cert chain or password anywhere in it, just proof that you hold the private key for a public key AD already trusts.

The stored value isn't a bare key either, it's a `KEYCREDENTIALLINK_BLOB` laid out in MS-ADTS 2.2.20, which is a version field followed by a run of entries that each carry a length, a one-byte type, and their data. The types include the key material, a key ID, a hash, a device ID, a couple of timestamps, and one named `CustomKeyInformation` that ends up being where this whole post lives.

## The abuse you already know

If you touch AD at all you know where this goes, because Elad Shamir published it back in 2021 as Shadow Credentials. Once you have write access to someone's `msDS-KeyCredentialLink` you drop in a key you control and authenticate as them over PKINIT, walking away with a TGT for the target without ever touching their password, and if you run the U2U trick against the PAC you pull their NT hash out as well, which gives you a durable way back in.

The whole bar is write access on that one attribute, which you get from GenericWrite, GenericAll, a WriteProperty scoped to it, or plain ownership of the object, and BloodHound draws the edge as AddKeyCredentialLink so you spot it on sight. Tools like pyWhisker, Whisker, and Certipy handle both the write and the authentication for you, so it's about as clean as takeovers get, and the preconditions for it turn up constantly in real environments.

That's the part people talk about, and it makes sense that nobody looks any closer, because the key you wrote is your own and nothing about it is going to surprise you. But the KDC quietly does something else with your key that I hadn't seen written up anywhere, and the whole thing hangs on that `CustomKeyInformation` entry I mentioned.

## The claim I went after

Pull a TGT from a key trust logon and read the PAC, and next to the normal group SIDs you'll spot a few sitting in the `S-1-18` range. Those are asserted-identity SIDs, and the KDC adds them to describe how you authenticated rather than who you are.

```
S-1-18-4   Key Trust Identity     you signed in with a key credential
S-1-18-5   MFA Key Property       the key was set up with MFA
S-1-18-6   Attested Key Property  the key was generated in and lives in a TPM
```

The bottom two are claims about the past, and since the KDC wasn't in the room when your key got provisioned, it has no first-hand knowledge of whether MFA actually happened or whether a TPM was ever involved, which raises the obvious question of how it decides to stamp them at all. The answer is that it reads `CustomKeyInformation`, which carries a one-byte Flags field where one bit means MFA was not used and another means the key is attested, and the KDC takes both of those bits entirely at their word.

I wrote a small tool to build KeyCredential blobs with whatever entries and flags I wanted, along with a second one to decrypt a TGT using the krbtgt key and dump the SIDs, and then I ran the obvious experiment against the same account and the same key trust logon while changing only that one flag byte.

```
CustomKeyInformation present, MFA_NOT_USED set   ->  no S-1-18-5
CustomKeyInformation present, flags cleared      ->  S-1-18-5
CustomKeyInformation entry absent                ->  S-1-18-5
ATTESTATION bit set                              ->  S-1-18-6
```

Two things jumped out of that. Clearing the MFA bit gets you the MFA SID, and leaving the whole `CustomKeyInformation` entry out gets it for you too, because the KDC reads a missing flag as a quiet confirmation that MFA happened, so the default is fail-open and the only way to not receive `S-1-18-5` is to explicitly declare that you skipped MFA. Attestation behaves the same way, so if you set the attestation bit on a plain software RSA key, one I generated with openssl that never went anywhere near a TPM, the KDC turns around and stamps `S-1-18-6`.

So I can make the KDC swear that a key did MFA and that it's hardware-backed while using a key that lives in a `.pem` file on a Linux box, which bothered me enough to keep going, though a SID in a ticket is only worth anything if something actually reads it, and that's where I spent the rest of my time.

## Does anything read them

This was the real question, and it's the line between an actual finding and a screenshot of an odd-looking SID that does nothing. Authentication policies read them, since a policy can gate access to an account with an SDDL condition and that condition can require a specific SID to be present in the caller's token. Microsoft's own Credential Guard documentation mentions this in passing while warning that access checks requiring `S-1-18-4` or `S-1-18-3` will break in certain states, so the pattern is real and Microsoft clearly knows people build on it.

I stood one up to be sure, using a service account called `svc01` with a policy that only allows authentication to it when the caller carries `S-1-18-5`, and then I asked for a service ticket two different ways. First with a normal key that carries no MFA SID in the token:

```
Kerberos SessionError: KDC_ERR_POLICY(KDC policy rejects request)
```

Then with the exact same setup but the MFA bit cleared, so the SID lands:

```
[*] Saving ticket in victim01@host_svc01.reflect.lab@REFLECT.LAB.ccache
```

Then I did the whole thing again for attestation, standing up a policy that demands `S-1-18-6` and watching my software key stroll straight through it. The entire point of attestation is to prove that a key can't be copied because it's trapped in silicon, and here a key sitting in a text file cleared the check without any trouble.

Authentication policies aren't the only reader, since Dynamic Access Control can put one of these SIDs into a file server's ACL through a conditional ACE and AD FS can read them out of the ticket for federated apps, though neither is common and DAC in particular is something almost nobody ended up running. I also checked delegation, since that's where a lot of Kerberos surprises tend to hide, and it ignores these SIDs completely while also giving you nothing here, because an S4U ticket gets minted without a real logon and never carries them in the first place. When I went looking for any third-party PAM or VPN gear that keys off them I came up empty, so the list of readers really is just the Microsoft-native access controls.

## The patch that misses it

Here's what moved this from a curiosity into something worth reporting. In January 2026 Microsoft changed domain controllers to reject validated writes of key credentials when the flag is missing, a behavior change that Michael Grafnetter spotted, and on paper that shuts the fail-open door I described earlier. It doesn't close it, and for two reasons. The block only covers the validated write path that the built-in enrollment client uses, and a raw LDAP write of the kind Shadow Credentials performs never touches that path, which I confirmed by landing a flag-absent raw write on a fully patched Server 2025 DC at build 26100.33296. The second gap is smaller and arguably worse, because even on the validated path the check only ever looks for the flag being absent, so setting it present but cleared goes straight through.

The common tools make this worse without even trying, because pyWhisker sets the flag to None for user targets, which is the cleared state that grants the MFA property, while Impacket leaves the entry out entirely, which is the absent state that grants it too. That means an off-the-shelf Shadow Credentials attack against a user account has been stamping the MFA property this entire time, with nobody forging anything on purpose, since the default behavior lies all on its own.

## What this actually gets you

I'd rather be honest about the scope here than sell it harder than it deserves. Nothing in Windows gates on these SIDs by default, so somebody has to write an authentication policy or a DAC rule that explicitly asks for them, and most environments never do, since gating specifically on the MFA or attestation SID is an advanced move you'd only find somewhere that already thinks hard about this kind of thing. This is not a bypass of MFA everywhere, and I'm not going to pretend that it is.

What it is comes in two pieces. In the environments that do lean on these SIDs, usually the tier-0 builds that care the most, a flag you control defeats both an MFA requirement and a hardware-key requirement off nothing but write access to one attribute on a fully current patch level. Everywhere else the claim is simply not trustworthy, because anything downstream that treats `S-1-18-5` as proof a session did MFA is trusting a bit that an attacker sets, and since the standard tooling sets that bit by accident, the signal is already dirty in plenty of places that never had a real attacker anywhere near them.

The KDC is making a promise it has no way to keep, telling the domain that a key did MFA or that it lives in hardware based on a byte the key's owner wrote, and for most of what these SIDs touch that reads as a broken assumption more than an open door, while in the places built to trust them it's a straight bypass. I also reported it to MSRC as a security feature bypass, so if you happen to run authentication policies that key off the `S-1-18` range it's worth going and looking at what you're actually trusting.
