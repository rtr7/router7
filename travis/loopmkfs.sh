#!/bin/bash
loopdev=$(sudo losetup -Pf --show /tmp/router7-qemu/disk.img)
sudo mkfs.ext4 -m 1 "${loopdev}p4"
sudo mount "${loopdev}p4" /mnt
# TODO: make github.com/gokrazy/serial-busybox work with GOARCH=amd64
sudo cp ~/src/busybox-1.22.0-amd64/busybox /mnt/sh || true
cat <<'EOT' | sudo tee /mnt/interfaces.json
{
    "interfaces": [
	{
	    "hardware_addr": "52:55:00:d1:55:03",
	    "name": "uplink0"
	},
	{
	    "hardware_addr": "52:55:00:d1:55:04",
	    "name": "lan0",
	    "addr": "10.254.0.1/24"
	}
    ]
}
EOT
sudo umount /mnt
sudo losetup -d "${loopdev}"
