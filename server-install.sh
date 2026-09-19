#!/usr/bin/env bash
# server-install.sh — BCA-Core29 installer for fresh Ubuntu 22.04 Server
# No Docker. Uses online Ubuntu repositories (internet required).
# Run as root from the project root:
#   sudo ./server-install.sh [--no-tests] [-j N]
set -euo pipefail

RUN_TESTS=1
JOBS="$(nproc)"
for arg in "$@"; do
    case "$arg" in
        --no-tests) RUN_TESTS=0 ;;
        -j*) JOBS="${arg#-j}" ;;
    esac
done

log() { echo "[server-install] $*"; }
die() { echo "[server-install] ERROR: $*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "run as root (sudo ./server-install.sh)"
export DEBIAN_FRONTEND=noninteractive

if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    [ "${VERSION_CODENAME:-}" = "jammy" ] || log "WARNING: expected Ubuntu 22.04 (jammy), found '${PRETTY_NAME:-unknown}' — continuing anyway"
fi

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB4_DIR="$PROJECT_DIR/offline/db4"

# ------------------------------------------------------------ preflight ----
AVAILABLE_KB="$(df / | awk 'NR==2 {print $4}')"
REQUIRED_KB=10485760  # 10 GB
if [ "$AVAILABLE_KB" -lt "$REQUIRED_KB" ]; then
    die "not enough disk space: ${AVAILABLE_KB}KB available, need ${REQUIRED_KB}KB (~10GB)"
fi

# ---------------------------------------------------------------- repos ---
log "fixing permissions on offline packages"
chmod -R a+rX "$PROJECT_DIR/offline/packages" 2>/dev/null || true
log "regenerating Packages index with correct paths"
PKG_DIR="$PROJECT_DIR/offline/packages"
if [ -d "$PKG_DIR" ]; then
    (cd "$PKG_DIR" && dpkg-scanpackages --multiversion . /dev/null 2>/dev/null | sed "s|Filename: \./|Filename: $PKG_DIR/|g" > Packages && gzip -f Packages)
    echo "deb [trusted=yes] file://$PKG_DIR ./" > /etc/apt/sources.list.d/atom-offline.list
fi
log "updating package lists"
apt-get update > /dev/null 2>&1

# ---------------------------------------------------------------- deps ----
log "installing build dependencies"
DEPS="build-essential cmake pkgconf python3 ccache curl wget git
      libevent-dev libboost-dev libsqlite3-dev
      qtbase5-dev qttools5-dev qttools5-dev-tools
      libqrencode-dev libminiupnpc-dev libnatpmp-dev libzmq3-dev"
apt-get install -y $DEPS || die "dependency install failed"

# ------------------------------------------------------------ bdb 4.8 ----
if [ ! -f /opt/db4/lib/libdb_cxx-4.8.a ]; then
    log "building Berkeley DB 4.8 from source"
    rm -rf /tmp/db4src && mkdir -p /tmp/db4src && cd /tmp/db4src
    if [ -f "$DB4_DIR/db-4.8.30.NC.tar.gz" ]; then
        cp "$DB4_DIR/db-4.8.30.NC.tar.gz" .
    else
        wget --no-check-certificate -q https://download.oracle.com/berkeley-db/db-4.8.30.NC.tar.gz
    fi
    echo "12edc0df75bf9abd7f82f821795bcee50f42cb2e5f76a6a281b85732798364ef  db-4.8.30.NC.tar.gz" > sha256sums
    sha256sum -c sha256sums || die "BDB tarball checksum mismatch"
    tar xzf db-4.8.30.NC.tar.gz
    cd db-4.8.30.NC
    if [ -f "$DB4_DIR/clang.patch" ]; then
        patch -p2 < "$DB4_DIR/clang.patch"
    else
        wget -q -O clang.patch https://gist.githubusercontent.com/LnL7/5153b251fd525fe15de69b67e63a6075/raw/7778e9364679093a32dec2908656738e16b6bdcb/clang.patch
        patch -p2 < clang.patch
    fi
    cd build_unix
    ../dist/configure --enable-cxx --disable-shared --disable-replication \
        --with-pic --prefix=/opt/db4 > /tmp/db4-configure.log 2>&1
    make -j"$JOBS" > /tmp/db4-build.log 2>&1
    make install > /tmp/db4-install.log 2>&1
    cd / && rm -rf /tmp/db4src
    log "BDB 4.8 installed to /opt/db4"
else
    log "BDB 4.8 already present at /opt/db4"
fi

# ---------------------------------------------------------------- build ---
log "configuring BCA-Core29"
cd "$PROJECT_DIR"
cmake -B build -DCMAKE_PREFIX_PATH=/opt/db4 -DWITH_BDB=ON -DBUILD_GUI=ON \
    -DBUILD_TESTS=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo > /tmp/atom-cmake.log 2>&1
log "compiling (-j$JOBS, this takes a while)"
cmake --build build -j"$JOBS" --target bitcoind bitcoin-cli bitcoin-wallet \
    bitcoin-tx bitcoin-qt test_bitcoin > /tmp/atom-build.log 2>&1
log "build finished"

if [ "$RUN_TESTS" = "1" ]; then
    log "running unit test suite"
    ./build/bin/test_bitcoin > /tmp/atom-unittests.log 2>&1
    log "unit tests passed"
else
    log "tests skipped (--no-tests)"
fi

mkdir -p releaseBIN
cp -f build/bin/bitcoind build/bin/bitcoin-cli build/bin/bitcoin-wallet \
      build/bin/bitcoin-tx build/bin/bitcoin-qt releaseBIN/
log "binaries in $PROJECT_DIR/releaseBIN:"
ls -la releaseBIN/
log "install complete — run ./releaseBIN/bitcoind -regtest to start"
