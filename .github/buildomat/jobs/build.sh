#!/usr/bin/env bash
#:
#: name = "build"
#: variety = "basic"
#: target = "omnios-r151046"
#: output_rules = [
#:	"/work/tarballs/*",
#: ]
#:

set -o errexit
set -o pipefail
set -o xtrace

privhdrs="https://stluc.manta.uqcloud.net/xlex/public/zfs-privhdrs-r151038.tar.gz"
jsonc_ver="0.16"
jsonc="https://s3.amazonaws.com/json-c_releases/releases/json-c-${jsonc_ver}.tar.gz"
ragel_ver="6.10"
ragel="http://www.colm.net/files/ragel/ragel-${ragel_ver}.tar.gz"

mkdir -p /work/dist

#
banner packages
#

pfexec pkg install \
  pkg:/driver/misc/ccid \
  pkg:/system/library/libpcsc \
  pkg:/developer/pkg-config \
  pkg:/developer/build/onbld \
  pkg:/ooce/developer/cmake

#
banner zfs headers
#

mkdir -p /work/zfs-priv
pushd /work/zfs-priv
curl ${privhdrs} | gtar -zxvf -
popd

#
banner ragel
#
mkdir -p /work/ragel
pushd /work/ragel
curl ${ragel} | gtar -zxf -
cd ragel-${ragel_ver}
./configure --prefix=/opt/ragel-${ragel_ver}
gmake -j2
pfexec gmake -j2 install
popd

#
banner libjson-c
#
mkdir -p /work/jsonc
pushd /work/jsonc
curl ${jsonc} | gtar -zxf -
cd json-c-${jsonc_ver}
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=/opt/pivy ..
gmake -j2

# install them to /opt/pivy now so we can use them for building pivy
pfexec gmake -j2 install
# make the pkgconfig file have -R in it
awk -F':[ ]+' '
  $1 == "Libs" { printf("%s: -R${libdir} %s\n", $1, $2); }
  $1 != "Libs" { print; }
' </opt/pivy/lib/pkgconfig/json-c.pc >/work/json-c.pc
pfexec cp /work/json-c.pc /opt/pivy/lib/pkgconfig/json-c.pc

# copy just the .so into the final pivy dist
pfexec /usr/sbin/install -d -u root -g bin /work/dist/opt/pivy/lib
pfexec /usr/sbin/install -f /work/dist/opt/pivy/lib -u root -g bin \
  /opt/pivy/lib/libjson-c.so.5.2.0
pfexec ln -s libjson-c.so.5.2.0 /work/dist/opt/pivy/lib/libjson-c.so.5
pfexec ln -s libjson-c.so.5 /work/dist/opt/pivy/lib/libjson-c.so
popd

#
banner build
#
export PATH=$PATH:/opt/onbld/bin/i386:/opt/ragel-${ragel_ver}/bin
export MAKE=gmake
export PKG_CONFIG_PATH=/opt/pivy/lib/pkgconfig:$PKG_CONFIG_PATH
gmake -j2 \
  USE_ZFS=yes \
  ZFS_PRIVATE_HEADERS=/work/zfs-priv \
  USE_JSONC=yes \
  PCSC_CFLAGS= PCSC_LIBS=-lpcsc
  prefix=/opt/pivy \
  bingroup=bin

#
banner install
#
pfexec gmake -j2 install \
  USE_ZFS=yes \
  USE_JSONC=yes \
  prefix=/opt/pivy \
  bingroup=bin \
  DESTDIR=/work/dist

#
banner tarball
#
mkdir -p /work/tarballs
pushd /work/dist
tar -cvzf /work/tarballs/pivy.tar.gz *
popd
