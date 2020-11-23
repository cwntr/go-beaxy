#!/usr/bin/env bash
GOOS="linux" GOARCH="amd64" go build -o beaxy
GOOS="windows" GOARCH="386" go build -o beaxy_win
