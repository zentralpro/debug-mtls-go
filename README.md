# debug-mtls

Simple tool to setup a certificate authority and serve a folder.

## 0 - Build

Install [go](https://golang.org/).

then

```bash
make
```

## 1 - Setup the CA

```bash
./dmtls setup --ca /path/to/the/CA/dir \
              --server-name name.of.the.server \
              --client-name name.of.the.client
```

A directory with all the certificates and keys will be created at `/path/to/the/CA/dir`.

**IMPORTANT** Install the `/path/to/the/CA/dir/debug-mtls.mobileconfig` profile!  It contains the CA root certificate and the client certificate with its corresponding key. After the install, you can use the `KeyChain.app` to verify that those items are present.

If you omit the options, default values will be used.

## 2 - Serve some files

```bash
./dmtls serve --ca /path/to/the/CA/dir \
              --root /path/to/the/files/dir
```

or

```bash
./dmtls serve --ca /path/to/the/CA/dir \
              --root /path/to/the/files/dir \
              --ip 127.0.0.1 \
              --port 8443
```

**IMPORTANT** Make sure that the `name.of.the.server` is pointing the the IP address used in the `dmtls serve` command (by default 0.0.0.0, so any IP address of the machine where the command is running). You can for example add it to the `/etc/hosts` file.
