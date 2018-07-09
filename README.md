# router7

TODO(stapelberg): travis badge, reportcard badge

router7 is a pure-Go implementation of a small home internet router. It comes with all the services required to make a [fiber7 internet connection](https://www.init7.net/en/internet/fiber7/) work (DHCPv4, DHCPv6, DNS, etc.).

Note that this project should be considered a (working!) tech demo. Feature requests will likely not be implemented, and see [CONTRIBUTING.md](CONTRIBUTING.md) for details about which contributions are welcome.

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

### Teensy rebootor

The cheap and widely-available [Teensy++ USB development board](https://www.pjrc.com/store/teensypp.html) comes with a firmware called rebootor, which is used by the [`teensy_loader_cli`](https://www.pjrc.com/teensy/loader_cli.html) program to perform hard resets.

This setup can be used to programmatically reset the apu2c4 (from `rtr7-recover`) by connecting the Teensy++ to the [apu2c4’s reset pins](http://pcengines.ch/pdf/apu2.pdf):
* connect the Teensy++’s `GND` pin to the apu2c4 J2’s pin 4 (`GND`)
* connect the Teensy++’s `B7` pin to the apu2c4 J2’s pin 5 (`3.3V`, resets when pulled to `GND`)

You can find a working rebootor firmware .hex file at https://github.com/PaulStoffregen/teensy_loader_cli/issues/38

## Architecture

router7 is based on [gokrazy](https://gokrazy.org/): it is an appliance which gets packed into a hard disk image, containing a FAT partition with the kernel, a read-only SquashFS partition for the root file system and an ext4 partition for permanent data.

The individual services can be found in [github.com/rtr7/router7/cmd](https://godoc.org/github.com/rtr7/router7/cmd).

* Each service runs in a separate process.
* Services communicate with each other by persisting state files. E.g., `cmd/dhcp4` writes `/perm/dhcp4/wire/lease.json`.
* A service notifies other services about state changes by sending them signal `SIGUSR1`.

### Configuration files

| File | Consumer(s) | Purpose |
|---|---|---|
| `/perm/interfaces.json` | `netconfigd` | Set IP/MAC addresses of `uplink0` and `lan0` |
| `/perm/portforwardings.json` | `netconfigd` | Configure nftables port forwarding rules |
| `/perm/dhcp6/duid` | `dhcp6` | Set DHCP Unique Identifier (DUID) for obtaining static leases |

### State files

| File | Producer | Consumer(s) | Purpose |
|---|---|---|---|
| `/perm/dhcp4/wire/ack` | `dhcp4` | `dhcp4` | last DHCPACK packet for renewals across restarts |
| `/perm/dhcp4/wire/lease.json` | `dhcp4` | `netconfigd` | Obtained DHCPv4 lease |
| `/perm/dhcp6/wire/lease.json` | `dhcp6` | `netconfigd` | Obtained DHCPv6 lease |
| `/perm/dhcp4d/leases.json` | `dhcp4d` | `dhcp4d`, `dnsd` | DHCPv4 leases handed out (including hostnames) |

### Available ports

| Port | Purpose |
|---|---|
| `<public>:8053` | `dnsd` metrics (forwarded requests)
| `<public>:8066` | `netconfigd` metrics (nftables counters)
| `<private>:80` | gokrazy web interface
| `<private>:67` | `dhcp4d`
| `<private>:58` | `radvd`
| `<private>:53` | `dnsd`
| `<private>:8077` | `backupd` (serve backup.tar.gz)
| `<private>:7733` | `diagd` (perform diagnostics)
| `<private>:5022` | `captured` (serve captured packets)

Here’s an example of the diagd output:

<img src="https://github.com/rtr7/router7/raw/master/2018-07-14-diagd.png"
width="800" alt="diagd output">

Here’s an example of the metrics when scraped with [Prometheus](https://prometheus.io/) and displayed in [Grafana](https://grafana.com/):

<img src="https://github.com/rtr7/router7/raw/master/2018-07-14-grafana.png"
width="800" alt="metrics in grafana">

## Installation

Connect your serial adapter ([usbcom1a](https://pcengines.ch/usbcom1a.htm) works well if you don’t have one already) to the apu2c4 and start a program to use it, e.g. `screen /dev/ttyUSB0 115200`. Then, power on the apu2c4 and configure it to do PXE boot:

* Press `F10` to enter the boot menu
* Press `3` to enter setup
* Press `n` to enable network boot
* Press `c` to move mSATA to the top of the boot order
* Press `e` to move iPXE to the top of the boot order
* Press `s` to save configuration and exit

Connect a network cable on `net0`, the port closest to the serial console port:

<img src="https://github.com/rtr7/router7/raw/master/devsetup.jpg"
width="800" alt="router7 development setup">

Next, build a router7 image:

```
go get -u github.com/gokrazy/tools/cmd/gokr-packer
mkdir /tmp/recovery
GOARCH=amd64 gokr-packer \
	-hostname=router7 \
	-overwrite_boot=/tmp/recovery/boot.img \
	-overwrite_mbr=/tmp/recovery/mbr.img \
	-overwrite_root=/tmp/recovery/root.img \
	-kernel_package=github.com/rtr7/kernel \
	-firmware_package=github.com/rtr7/kernel \
	-gokrazy_pkgs=github.com/gokrazy/gokrazy/cmd/ntp \
	-serial_console=ttyS0,115200n8 \
	github.com/rtr7/router7/cmd/...
```

Run `rtr7-recover -boot=/tmp/recovery/boot.img -mbr=/tmp/recovery/mbr.img -root=/tmp/recovery/root.img` to:

* trigger a reset if a Teensy with the rebootor firmware is attached
* serve a DHCP lease to all clients which request PXE boot (i.e., your apu2c4)
* serve via TFTP:
  * the PXELINUX bootloader
  * the router7 kernel
  * an initrd archive containing the rtr7-recovery-init program and mke2fs
* serve via HTTP the boot and root images
* optionally serve via HTTP a backup.tar.gz image containing files for /perm (e.g. for moving to new hardware, rolling back corrupted state, or recovering from a disk failure)
* exit once the router successfully wrote the images to disk

### Updates

Run e.g. `rtr7-safe-update -updates_dir=$HOME/router7/updates` to:

* verify the router currently has connectivity, abort the update otherwise
* download a backup archive of `/perm`
* build a new image
* update the router
* wait until the router restored connectivity, roll back the update using `rtr7-recover` otherwise

The update step uses kexec to reduce the downtime to approximately 15 seconds.

### Manual Recovery

Given `rtr7-safe-update`’s safeguards, manual recovery should rarely be required.

To manually roll back to an older image, invoke `rtr7-safe-update` via the
`recover.bash` script in the image directory underneath `-updates_dir`, e.g.:

```
% cd ~/router7/updates/2018-07-03T17:33:52+02:00
% ./recover.bash
```
