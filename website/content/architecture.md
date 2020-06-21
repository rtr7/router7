---
title: "router7: architecture"
menu:
  main:
    title: "Architecture"
    weight: 20
---

# Architecture

router7 is based on [gokrazy](https://gokrazy.org/): it is an appliance which gets packed into a hard disk image, containing a FAT partition with the kernel, a read-only SquashFS partition for the root file system and an ext4 partition for permanent data.

The individual services can be found in [github.com/rtr7/router7/cmd](https://pkg.go.dev/github.com/rtr7/router7/cmd)

* Each service runs in a separate process.
* Services communicate with each other by persisting state files. E.g., `cmd/dhcp4` writes `/perm/dhcp4/wire/lease.json`.
* A service notifies other services about state changes by sending them signal `SIGUSR1`.

## Configuration files

{{<table "table table-striped table-bordered">}}
| File | Consumer(s) | Purpose |
|---|---|---|
| `/perm/interfaces.json` | `netconfigd` | Set IP/MAC addresses of `uplink0` and `lan0` |
| `/perm/portforwardings.json` | `netconfigd` | Configure nftables port forwarding rules |
| `/perm/dhcp6/duid` | `dhcp6` | Set DHCP Unique Identifier (DUID) for obtaining static leases |
{{</table>}}

## State files

{{<table "table table-striped table-bordered">}}
| File | Producer | Consumer(s) | Purpose |
|---|---|---|---|
| `/perm/dhcp4/wire/ack` | `dhcp4` | `dhcp4` | last DHCPACK packet for renewals across restarts |
| `/perm/dhcp4/wire/lease.json` | `dhcp4` | `netconfigd` | Obtained DHCPv4 lease |
| `/perm/dhcp6/wire/lease.json` | `dhcp6` | `netconfigd`, `radvd` | Obtained DHCPv6 lease |
| `/perm/dhcp4d/leases.json` | `dhcp4d` | `dhcp4d`, `dnsd` | DHCPv4 leases handed out (including hostnames) |
{{</table>}}

## Available ports

{{<table "table table-striped table-bordered">}}
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
{{</table>}}

Here’s an example of `cmd/diagd` output:

<img src="https://github.com/rtr7/router7/raw/master/2018-07-14-diagd.png"
width="800" alt="diagd output">

Here’s an example of `cmd/netconfigd` metrics when scraped with [Prometheus](https://prometheus.io/) and displayed in [Grafana](https://grafana.com/):

<img src="https://github.com/rtr7/router7/raw/master/2018-07-14-grafana.png"
width="800" alt="metrics in grafana">
