## legowrap-sakuraclouddns

A command line tool to manage and ensure SSL/TLS certificates are updated using Sakura Cloud DNS

## How to build

To build the tool, first set up [Go binary](https://go.dev/) and then run the following command:

```
go build -trimpath -tags netgo,osusergo
```

## Set up

### Set up dependent tools: `sops` and `age`

Download and install `sops` and `age` command line tools.

* [getsops/sops: Simple and flexible tool for managing secrets](https://github.com/getsops/sops)
* [FiloSottile/age: A simple, modern and secure encryption tool (and Go library) with small explicit keys, no config options, and UNIX-style composability.](https://github.com/FiloSottile/age)

### Generate an `age` key file

```
mkdir -p ~/.config/sops/age
age-keygen -o ~/.config/sops/age/keys.txt
```

### Set up the configuration file

Copy the unencrypted example config file and modify it with your favorite editor.
You can leave the `lego.account` key blank since you will update it in the section below.

For Let's Encrypt, edit `token` and `secret` in `sakura_cloud_dns`.

```
cp legowrap-sakuraclouddns-example.decrypted.yaml legowrap-sakuraclouddns.decrypted.yaml
vim legowrap-sakuraclouddns.decrypted.yaml
```

For ZeroSSL, generate EAB Credentials at [ACME Documentation - ZeroSSL](https://zerossl.com/documentation/acme/) and edit `kid` and `hmac` values at `lego.register` in the file. Also edit `token` and `secret` in `sakura_cloud_dns`.

```
cp legowrap-sakuraclouddns-ZeroSSL-example.decrypted.yaml legowrap-sakuraclouddns.decrypted.yaml
vim legowrap-sakuraclouddns.decrypted.yaml
```

Then, encrypt the configuration file.

```
sops encrypt --age $(age-keygen -y ~/.config/sops/age/keys.txt) legowrap-sakuraclouddns.decrypted.yaml > legowrap-sakuraclouddns.yaml
```

Once the configuration file is encrypted, you can edit it with the following command:

```
sops edit legowrap-sakuraclouddns.yaml
```

Warning: Do not edit it with a standard text editor, even for unencrypted fields, as doing so will prevent `sops` from decrypting the file correctly.

### Register your Let's Encrypt account and update the configuration file

```
legowrap-sakuraclouddns register --email=_YOUR_EMAIL_ADDRESS_HERE_ | sops set --value-stdin legowrap-sakuraclouddns.yaml '["lego"]["account"]'
```

### Move the configuration file to the default path

```
mv legowrap-sakuraclouddns.yaml /usr/local/etc/
```

Alternatively, you can specifiy the config file path with the global `--config` flag of the `legowrap-sakuraclouddns` CLI tool.


## Issue the certificate

Run the following command to issue the certificate for the first time:

```
legowrap-sakuraclouddns ensure-updated --domain 'example.jp,*.example.jp' --skip-get-cert --skip-renew
```

Run the following command to renew the certificate of the target server:

```
legowrap-sakuraclouddns ensure-updated --domain 'example.jp,*.example.jp'
```

The CLI gets the certificate from the server and only issues a new certificate when the expiration date is near.
