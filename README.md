filterefs
=========

`mount --bind / somewhere` with POSIX extended regular expression filters to control which files can be read and/or written.

filterefs tries to be efficient and simple.

Dependencies
------------
* fuse (&gt;= 2.6, &lt; 3.0)

Build
-----
Just run `make`.
The project uses `__attribute__((constructor))`, you should use a C compiler that supports it.

Usage
-----

Check `filterefs -h` for details. Here is a quick example:

```bash
$ cd /tmp

$ cat > ./readable <<'EOF'
/dev(/(full|null|urandom|random|zero))?
/(bin|lib|lib64|usr|tmp|etc|proc)(/.*)?
!/proc/1(/.*)?
EOF

$ cat > ./writable <<'EOF'
/tmp(/.*)?
!/tmp/abc
EOF

$ mkdir -p ./root

# `-o allow_other` is required for chroot to work
$ filterefs ./root -r ./readable -w ./writable -o allow_other

$ sudo chroot ./root /bin/sh

$ ls /
bin  dev  etc  lib  lib64  proc  tmp  usr

$ ls /dev
full  null  random  urandom  zero


# this is okay
$ touch /tmp/def

# these will fail
$ touch /tmp/abc
$ mv /tmp/def /tmp/abc
```

Notes
-----

The config files must NOT contain user-generated-content.
filterefs does not verify every regular expression and is vulnerable to regular expression injection.

FUSE enforces `-o nodev,nosuid` for non-root users. If you want to use device files, run filterefs as root and add `-o dev`.

License
-------
GPL2.
