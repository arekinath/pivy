#!/usr/bin/env bash
#:
#: name = "build"
#: variety = "basic"
#: target = "omnios-r151038"
#: output_rules = [
#:	"/work/tarballs/*",
#: ]
#:

set -o errexit
set -o pipefail
set -o xtrace

privhdrs="https://stluc.manta.uqcloud.net/xlex/public/zfs-privhdrs-r151038.tar.gz"

banner install packages
pfexec pkg install \
  pkg:/driver/misc/ccid \
  pkg:/system/library/libpcsc \
  pkg:/developer/pkg-config \
  pkg:/developer/build/onbld

banner grab zfs private headers
mkdir -p /work/zfs-priv
pushd /work/zfs-priv
curl ${privhdrs} | gtar -zxvf -
popd

banner build
export PATH=$PATH:/opt/onbld/bin/i386
export MAKE=gmake
gmake -j2 \
  USE_ZFS=yes \
  ZFS_PRIVATE_HEADERS=/work/zfs-priv \
  PCSC_CFLAGS= PCSC_LIBS=-lpcsc
  prefix=/opt/pivy \
  bingroup=bin

banner install
mkdir -p /work/dist
pfexec gmake -j2 install \
  USE_ZFS=yes \
  prefix=/opt/pivy \
  bingroup=bin \
  DESTDIR=/work/dist

banner tarball
mkdir -p /work/tarballs
pushd /work/dist
tar -czf /work/tarballs/pivy.tar.gz *
popd
