OpenBSD build guide
======================
(updated for OpenBSD 6.7)

This guide describes how to build bitcoind and command-line utilities on OpenBSD.

OpenBSD is most commonly used as a server OS, so this guide does not contain instructions for building the GUI.

Preparation
-------------

Run the following as root to install the base dependencies for building:

```bash
pkg_add git gmake libevent libtool boost
pkg_add autoconf # (select highest version, e.g. 2.69)
pkg_add automake # (select highest version, e.g. 1.16)
pkg_add python # (select highest version, e.g. 3.8)

git clone https://github.com/bitcoin/bitcoin.git
```

See [dependencies.md](dependencies.md) for a complete overview.

**Important**: From OpenBSD 6.2 onwards a C++11-supporting clang compiler is
part of the base image, and while building it is necessary to make sure that
this compiler is used and not ancient g++ 4.2.1. This is done by appending
`CC=cc CC_FOR_BUILD=cc CXX=c++` to configuration commands. Mixing different
compilers within the same executable will result in errors.

### OpenSSL

OpenBSD uses a replacement of OpenSSL: LibreSSL. This can cause compatibility issues, hence `./configure` will bark if you try to compile with this library:

    Detected LibreSSL: This is NOT supported, and may break consensus compatibility!

To install a 'real' OpenSSL use:

    pkg_add openssl
   
Any program linked against this library can only be used after setting the dynamic library path:
    
    export LD_LIBRARY_PATH="/usr/local/lib/eopenssl"

(otherwise there will be an error about not being able to find `libcrypto.so.1.0`)

Alternatively, pass `--with-libressl` to `./configure`, however as the warning says, this is NOT supported, and may cause problems syncing the chain, or the node to fork off the network in unexpected circumstances.

### Building BerkeleyDB

BerkeleyDB is only necessary for the wallet functionality. To skip this, pass
`--disable-wallet` to `./configure` and skip to the next section.

It is recommended to use Berkeley DB 4.8. You cannot use the BerkeleyDB library
from ports, for the same reason as boost above (g++/libstd++ incompatibility).
If you have to build it yourself, you can use [the installation script included
in contrib/](/contrib/install_db4.sh) like so:

```bash
./contrib/install_db4.sh `pwd` CC=cc CXX=c++
```

from the root of the repository. Then set `BDB_PREFIX` for the next section:

```bash
export BDB_PREFIX="$PWD/db4"
```

### Building Bitcoin Core

**Important**: Use `gmake` (the non-GNU `make` will exit with an error).

Preparation:
```bash

# Replace this with the autoconf version that you installed. Include only
# the major and minor parts of the version: use "2.69" for "autoconf-2.69p2".
export AUTOCONF_VERSION=2.69

# Replace this with the automake version that you installed. Include only
# the major and minor parts of the version: use "1.16" for "automake-1.16.1".
export AUTOMAKE_VERSION=1.16

./autogen.sh
```
Make sure `BDB_PREFIX` is set to the appropriate path from the above steps.

To configure with wallet:
```bash
./configure --with-gui=no CC=cc CXX=c++ \
    SSL_CFLAGS="-I/usr/local/include/eopenssl" SSL_LIBS="-L/usr/local/lib/eopenssl -lssl" \
    CRYPTO_CFLAGS="-I/usr/local/include/eopenssl" CRYPTO_LIBS="-L/usr/local/lib/eopenssl -lcrypto" \
    BDB_LIBS="-L${BDB_PREFIX}/lib -ldb_cxx-4.8" \
    BDB_CFLAGS="-I${BDB_PREFIX}/include" \
    MAKE=gmake
```

To configure without wallet:
```bash
./configure --disable-wallet --with-gui=no CC=cc CC_FOR_BUILD=cc CXX=c++ \
    SSL_CFLAGS="-I/usr/local/include/eopenssl" SSL_LIBS="-L/usr/local/lib/eopenssl -lssl" \
    CRYPTO_CFLAGS="-I/usr/local/include/eopenssl" CRYPTO_LIBS="-L/usr/local/lib/eopenssl -lcrypto" \
    MAKE=gmake
```

Build and run the tests:
```bash
gmake # use -jX here for parallelism
gmake check
```

Resource limits
-------------------

If the build runs into out-of-memory errors, the instructions in this section
might help.

The standard ulimit restrictions in OpenBSD are very strict:

    data(kbytes)         1572864

This is, unfortunately, in some cases not enough to compile some `.cpp` files in the project,
(see issue [#6658](https://github.com/bitcoin/bitcoin/issues/6658)).
If your user is in the `staff` group the limit can be raised with:

    ulimit -d 3000000

The change will only affect the current shell and processes spawned by it. To
make the change system-wide, change `datasize-cur` and `datasize-max` in
`/etc/login.conf`, and reboot.
