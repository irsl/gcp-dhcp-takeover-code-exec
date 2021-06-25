#!/bin/bash

go get github.com/initstring/dhcp4
go build flood.go
gcc randr.c -o randr

