SUDO=GOPATH=$(shell go env GOPATH) sudo --preserve-env=GOPATH

PKGS := github.com/rtr7/router7/cmd/... \
	github.com/gokrazy/breakglass \
	github.com/stapelberg/dyndns \
	github.com/gokrazy/timestamps \
	github.com/stapelberg/zkj-nas-tools/wolgw \
	github.com/gokrazy/gdns \
	github.com/stapelberg/prober7/cmd/probe

image:
ifndef DIR
	@echo variable DIR unset
	false
endif
	go install github.com/gokrazy/tools/cmd/gokr-packer
	GOARCH=amd64 gokr-packer \
		-gokrazy_pkgs=github.com/gokrazy/gokrazy/cmd/ntp,github.com/gokrazy/gokrazy/cmd/randomd \
		-kernel_package=github.com/rtr7/kernel \
		-firmware_package=github.com/rtr7/kernel \
		-overwrite_boot=${DIR}/boot.img \
		-overwrite_root=${DIR}/root.img \
		-overwrite_mbr=${DIR}/mbr.img \
		-serial_console=ttyS0,115200n8 \
		-hostname=router7 \
		${PKGS}

recover: #test
	go install \
		github.com/gokrazy/tools/cmd/gokr-packer \
		github.com/rtr7/tools/cmd/rtr7-recover
	GOARCH=amd64 gokr-packer \
		-gokrazy_pkgs=github.com/gokrazy/gokrazy/cmd/ntp,github.com/gokrazy/gokrazy/cmd/randomd \
		-kernel_package=github.com/rtr7/kernel \
		-firmware_package=github.com/rtr7/kernel \
		-overwrite_boot=/tmp/recovery/boot.img \
		-overwrite_root=/tmp/recovery/root.img \
		-serial_console=ttyS0,115200n8 \
		-hostname=router7 \
		${PKGS}
	${SUDO} /home/michael/go/bin/rtr7-recover \
		-boot=/tmp/recovery/boot.img \
		-root=/tmp/recovery/root.img

test:
	# simulate recover (quick, for early for feedback)
	go build ${PKGS} github.com/rtr7/tools/cmd/...
	go test -count=1 -v -race github.com/rtr7/router7/internal/...
	# integration tests
	${SUDO} $(shell go env GOROOT)/bin/go test -count=1 -v -race github.com/rtr7/router7/...

testdhcp:
	go test -v -coverprofile=/tmp/cov github.com/rtr7/router7/internal/dhcp4d
#&& go tool cover -html=/tmp/cov

strace:
	# simulate recover (quick, for early for feedback)
	go build ${PKGS} github.com/rtr7/tools/cmd/...
	go test -v -race github.com/rtr7/router7/internal/...
	# integration tests
	(cd /tmp && go test -c router7) && ${SUDO} strace -f -o /tmp/st -s 2048 /tmp/router7.test -test.v #-test.race

update:
	rtr7-safe-update -build_command='make -C ~/router7 image DIR=$GOKR_DIR'
