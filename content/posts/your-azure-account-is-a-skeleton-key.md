---
title: Your Azure account is a Skeleton Key
tags:
  - Azure
  - Security
date: '2018-06-24 13:26:39'
---


This weekend I was out of town to visit my family. I normally carry an
`identity` USB stick that contains all of my (encrypted) private keys for
various servers with me whenever I travel, so that I can work from anywhere, but
this time I went by bicycle and wanted to travel light and it didn't occur to me
that I might have some time to work while I was visiting. Long story short, I
woke up early and wanted to get a few things out of the way, but realized there
was one small problem: I had no access to any of my servers or files.

Initially, I was playing around with [CTF][ctf] challenges and decided to tackle
the ones where I didn't need any (or few) tools to work on, but I quickly needed
at the very least a shell to run helper commands. Not wanting to pollute a
computer that doesn't belong to me with software, I was determined to get access
to my servers.

The only thing I had access to: Azure Portal.

[ctf]: https://www.ringzer0team.com "RingZer0 CTF"


# Hardened Virtual Machines?

Microsoft Azure's portal lets developers or operations people manage their
deployments, resources and subscriptions from a single convenient dashboard. The
portal comes with a very sophisticated access control system that lets
administrators granularly control who has access to what.

By default, virtual machines created in Azure have a root user with SSH enabled,
allow password login over SSH and provide a web SSH shell from the portal. One
of the first hardening steps that I had taken was to disable all of those
things. For a while, I thought that was enough. Not being able to spawn the web
SSH shell, nor connect to the VM via SSH, I looked around for other ways that I
could run something on the virtual machine.

As it turns out, there is a third way to execute code: The `Run Command` tab
in the VM's blade. This command bypasses all configurations on the virtual
machine and caues it to download whatever script you type in and execute it as a
root user. The VM agent (Azure's daemon that runs on the machine) then sends all
of `stdout` and `stderr` back to the portal, where it is nicely displayed to
you. Cool, this is exactly what I wanted.

# Injecting a new SSH keypair

I ran the following script and got myself a brand new (temporary) keypair that I
can use to login remotely until I get back home:

```sh
DIR=/home/me/tmp
mkdir "$DIR"

# Create a passphrase-less keypair
ssh-keygen -b 2048 -t rsa -N "" -f "$DIR/recovery.key"

# Add the key to authorized logon keys
cat "$DIR/recovery.key.pub" >> "$DIR/.ssh/authorized_keys"

# Dump the private key
cat "$DIR/recovery.key"
```

With this, all I needed to do is save the private key to the workstation I'm
using and add a passphrase to it. Once that's done. I can spawn a puTTY session
and `srm` the plaintext key from my Azure VM's disk. Once I leave, all I have to
do is remove the key entry from `~/.ssh/authorized_keys` to make sure the key is
no longer allowed to connect.

Note that this method is non-destructive and does not reset the SSH config,
which another option (`Reset Password`) available in the portal lets you do.

# Take aways

While none of this is ground breaking or surprising at all (after all, this is
the management portal for Azure resources), I felt like it was worth reiterating
that *such portals also need to be secured, because they act as a skeleton key
into your infrastructure.*

There is no doubt that these recovery features serve great purpose for
operational people and developers alike, but they also imply that any hardening
on your VM is rendered useless if you do not also secure your Azure account.

I used Azure, but I'm sure that all cloud platforms have similar functionality
in their portals. This can also be extended to every resource in the
infrastructure, such as storage accounts, message queues and so on.

# Summary

- Secure your cloud management accounts with two-factor and strong passphrases
- Hardening virtual machines is good but not enough
- Apply proper access control
- Management portals should be treated as very sensitive information
