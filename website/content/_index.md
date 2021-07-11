---
title: "router7: a small home internet router completely written in Go"
menu:
  main:
    title: "Home"
    weight: 10
---

# router7

router7 is a pure-Go implementation of a small home internet router. It comes with all the services required to make a [fiber7 internet connection](https://www.init7.net/en/internet/fiber7/) work (DHCPv4, DHCPv6, DNS, etc.).

Note that this project should be considered a (working!) tech demo. Feature requests will likely not be implemented, and see [CONTRIBUTING.md](https://github.com/rtr7/router7/blob/master/CONTRIBUTING.md) for details about which contributions are welcome.

## Motivation

Before starting router7, I was using the [Turris Omnia](https://omnia.turris.cz/en/) router running OpenWrt. That worked fine up until May 2018, when an automated update pulled in a new version of [odhcp6c](https://git.openwrt.org/?p=project/odhcp6c.git;a=shortlog), OpenWrt’s DHCPv6 client. That version is incompatible with fiber7’s DHCP server setup (I think there are shortcomings on both sides).

It was not only quicker to develop my own router than to wait for either side to resolve the issue, but it was also a lot of fun and allowed me to really tailor my router to my needs, experimenting with a bunch of interesting ideas I had.

## Project goals

* Maximize internet connectivity: retain the most recent DHCP configuration across reboots and even after its expiration (chances are the DHCP server will be back before the configuration stops working).
* Unit/integration tests use fiber7 packet capture files to minimize the chance of software changes breaking my connectivity.
* Safe and quick updates
  * Auto-rollback of updates which result in loss of connectivity: the diagnostics daemon assesses connectivity state, the update tool reads it and rolls back faulty updates.
  * Thanks to kexec, updates translate into merely 13s of internet connectivity loss.
* Easy debugging
  * Configuration-related network packets (e.g. DHCP, IPv6 neighbor/router advertisements) are stored in a ring buffer which can be streamed into [Wireshark](https://www.wireshark.org/), allowing for live and retro-active debugging.
  * The diagnostics daemon performs common diagnostic steps (ping, traceroute, …) for you.
  * All state in the system is stored as human-readable JSON within the `/perm` partition and can be modified.

## Hardware

The reference hardware platform is the [PC Engines™ apu2c4](https://pcengines.ch/apu2c4.htm) system board. It features a 1 GHz quad core amd64 CPU, 4 GB of RAM, 3 Ethernet ports and a DB9 serial port. It conveniently supports PXE boot, the schematics and bootloader sources are available. I recommend the [msata16g](https://pcengines.ch/msata16g.htm) SSD module for reliable persistent storage and the [usbcom1a](https://pcengines.ch/usbcom1a.htm) serial adapter if you don’t have one already.

Other hardware might work, too, but is not tested.
