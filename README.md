[![Crates.io badge](https://img.shields.io/crates/v/agnos?style=flat-square)](https://crates.io/crates/agnos)
[![github release badge badge](https://img.shields.io/github/v/release/krtab/agnos?style=flat-square)](https://github.com/krtab/agnos/releases/latest)
![github downloads badge](https://img.shields.io/github/downloads/krtab/agnos/total?style=flat-square)
<br/>
<img src="resources/Banner-optimized.png" alt="drawing" width="372"/>
<br/>
[<img src="resources/red-iron.png" alt="This project is proudly sponsored by Red Iron, the Rust division of OCamlPro" width="372"/>](https://red-iron.eu/)


<!-- TOC ignore:true -->
# Presentation

For an introduction to the ACME protocol and its DNS verification part, you can refer to our beta release [blog post](https://ocamlpro.com/blog/2022_10_05_agnos_0.1.0-beta).

Agnos is a single-binary program allowing you to easily obtain certificates (including wildcards) from [Let's Encrypt](https://letsencrypt.org/) using [DNS-01](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge) challenges. It answers Let's Encrypt DNS queries on its own, bypassing the need for API calls to your DNS provider.

<!-- TOC ignore:true -->
## Why


DNS-01 is summarized by Let's Encrypt documentation as such:

> <!-- TOC ignore:true -->
> ### Pros
>
> - You can use this challenge to issue certificates containing wildcard domain names.
> - It works well even if you have multiple web servers.
>
> <!-- TOC ignore:true -->
> ### Cons
>
> - Keeping API credentials on your web server is risky.
> - Your DNS provider might not offer an API.
> - Your DNS API may not provide information on propagation times.

By serving its own DNS answers, agnos:

- Nullify the need for API and API credentials
- Nullify all concerns regarding propagation times

Hence, **agnos removes virtually all downsides of dns-01 challenges**.

<!-- TOC ignore:true -->
## How


Agnos leverages let's encrypt capability to follow DNS `NS` records. It requires you to add to your DNS zone:

1. An `A` (or `AAAA`) record pointing to the public-facing IP address of the server on which agnos will run. On this server, UDP port 53 (the one used by DNS) should be open and free.
2. For each domain you will want to validate, an `NS` record for the corresponding `_acme-challenge` sub-domain, indicating that agnos should be used as a name server for this specific domain.

<!-- TOC ignore:true -->
# Table of content

<!-- TOC -->

- [Installation](#installation)
    - [Released binary](#released-binary)
    - [Packages](#packages)
    - [Packaging on other systems](#packaging-on-other-systems)
    - [Building](#building)
    - [Setting capabilities to not run agnos as root](#setting-capabilities-to-not-run-agnos-as-root)
- [Usage](#usage)
    - [Let's Encrypt accounts](#lets-encrypt-accounts)
    - [Agnos configuration](#agnos-configuration)
        - [General](#general)
        - [Accounts](#accounts)
        - [Certificates](#certificates)
    - [Configuration of your DNS provider](#configuration-of-your-dns-provider)
    - [Running agnos](#running-agnos)
    - [Systemd units](#systemd-units)
- [Developers](#developers)
    - [Integration testing](#integration-testing)
- [User feedback requested](#user-feedback-requested)

<!-- /TOC -->

# Installation

These instructions are given for a Linux system but a similar process will likely work on all Unixes, and maybe windows.

## Released binary

Pre-compiled binaries for Linux/amd64 are available for every tagged [release](https://github.com/krtab/agnos/releases). Be aware that they are statically built using musl and vendoring their own openssl so that they can easily be installed even on older distributions.

## Packages

Packages are available on the following systems. Thanks to their authors! Please note that these packages are done under the sole responsibiltiy of their author and not vetted by me.

- ArchLinux's [AUR](https://aur.archlinux.org/packages/agnos)
- [NixOs](https://github.com/NixOS/nixpkgs/tree/nixos-unstable/pkgs/by-name/ag/agnos)
- [Docker](https://hub.docker.com/r/epiceric/agnos)

## Packaging on other systems

If you have packaged agnos for another system, feel free to open a PR to add it to the list.

## Building

Agnos is written in Rust. To build it you will need to have the rust toolchain installed. On most distributions, this should be done using [rustup](https://rustup.rs).

Once you have obtained the source, the following command will build the binaries and put them in the root directory of the repo.

```bash
cd agnos/
make build-release
```

or more explicitly:

```bash
cargo build --locked --bins --release
strip target/release/agnos
strip target/release/agnos-generate-accounts-keys
ln target/release/agnos agnos
ln target/release/agnos-generate-accounts-keys agnos-generate-accounts-keys
```

## Setting capabilities to not run agnos as root

Because agnos listen on the low-numbered port 53, it requires special privileges. Running it as root will do, but if you (understandably) don't want to do that, the following command is for you:

```bash
# as root
setcap 'cap_net_bind_service=+ep' agnos
# agnos is the file of the binary as compiled above
```

# Usage

## Let's Encrypt accounts

Let's Encrypt accounts are identified by an e-mail address and a private RSA key. To generate such a key, use the following command:

```shell
openssl genrsa 2048 > /path/to/store/the/key.pem
```

or if you prefer a larger key:

```shell
openssl genrsa 4096 > /path/to/store/the/key.pem
```

Alternatively, you can use the provided `agnos-generate-accounts-keys` binary to automatically generate private keys for the accounts listed in the configuration file.

```bash
agnos-generate-accounts-keys --key-size 4096 your_config.toml
```

## Agnos configuration

Agnos is configured via a single [TOML](https://toml.io/) file. A commented example is available in [config_example.toml](https://github.com/krtab/agnos/blob/main/config_example.toml).

It is advised to use absolute rather than relative paths in the configuration file.

There are three "levels" in the configuration:

### 1. General

The general configuration level is where the IP address to listen on is provided.

```toml
dns_listen_addr = "192.0.2.91:53"
```

### 2. Accounts

Several Let's Encrypt accounts can be specified. For each account, an e-mail address and the path to the account RSA private key must be provided.

```toml
[[accounts]]
email= "contact@doma.in"
private_key_path = "priv_key.pem"
```

### 3. Certificates

For each account, several certificates can be ordered. Each certificate can cover multiple domains. On disk, a certificate is represented by two files: the full certificate chain, and the private key of the certificate (different from the account private key). This certificate private key is regenerated on each certificate renewal by default but if one is already present on disk, it can be reused by setting the `reuse_private_key` option to true
In the configuration file, `accounts.certificates` is a TOML [array of tables](https://toml.io/en/v1.0.0#array-of-tables) meaning that several certificates can be attached to one account by writing them one after the other.

```toml
# A first certificate ordered for that account.
[[accounts.certificates]]
domains =  ["doma.in","*.doma.in"]
fullchain_output_file = "fullchain_A.pem"
key_output_file = "cert_key_A.pem"
# Renew certificate 30 days in advance of its expiration
# (this is the default value and can be omitted).
renewal_days_advance = 30
# Regenerate a private key for the certificate on each renewal
# (this is the default value and can be omitted).
reuse_private_key = false 

# A second certificate ordered for that account.
[[accounts.certificates]]
renewal_days_advance = 21 # Renew certificate 21 days in advance of its expiration.
domains =  ["examp.le","another.examp.le","and.a.completely.different.one"]
fullchain_output_file = "fullchain_B.pem"
key_output_file = "cert_key_B.pem"
# Re-use the existing private key.
# If no key is present at `key_output_file`, a new one will be generated.
reuse_private_key = true
```

## Configuration of your DNS provider

Say that we have the following domains we want to obtain a certificate (or multiple certificates) for: 
- `doma.in`
- its wildcard variant: `*.doma.in`
- `examp.le`
- and `another.examp.le`. 

Notice here that we are not requesting a certificate for `*.examp.le` but only for one subdomain: `another.examp.le`.

Let's encrypt DNS-01 challenge is going to ask for TXT DNS records on the following three domains: 
- `_acme-challenge.doma.in` (for both `doma.in` and its wildcard)
- `_acme-challenge.examp.le`
- `_acme-challenge.another.examp.le`

Let's assume that agnos is going to run on a server whose public-facing IP address is `192.0.2.91`[^rfc5737]. The goal is to indicate that the three `_acme_challenge` domains cited above are managed by agnos using `NS` DNS records. `NS` records usually point to domain names, so we will also set an `A` record on `agnos-ns.doma.in` to point to `192.0.2.91` (here `agnos-ns.doma.in` is entirely arbitrary, it could be another, completely independent domain, you control, like `my-agnos.com`).

[^rfc5737]: This IP (`192.0.2.19`) has no peculiar significance. It is one of the example IPs usable in documentation defined in [RFC 5737](https://datatracker.ietf.org/doc/rfc5737/).

We create the following records:

In the zone of `doma.in`
```
agnos-ns.doma.in            A       192.0.2.91
_acme-challenge.doma.in     NS      agnos-ns.doma.in
```

In the zone of `examp.le`
```
_acme-challenge.examp.le            NS      agnos-ns.doma.in
_acme-challenge.another.examp.le    NS      agnos-ns.doma.in
```

**Note:** Though it may seem cumbersome, this must only be done once from your DNS provider web interface. Once it is done, you will never have to touch a `TXT` record.

## Running agnos

`agnos` takes a single command line argument, the path to its configuration file, and two optional flags: `--no-staging` to use Let's Encrypt production server, and `--debug` to display more debug information. Help is available via `agnos --help`.

When running, it checks whether the certificates of the full chain are going to expire in the next 30 days (by default), and only renew them in that case, so it is suitable to be used in a cron job.

## Systemd units

A systemd unit and timers are provided in the `systemd` folder of this repo.

# Developers

PRs and issues are very welcome.

Build using usual `cargo` commands.

## Integration testing

Integration testing is done using nix-shell. Launch it with `nix-shell integration-testing/shell.nix --pure --run agnos-test-script`.

# User feedback requested

If you are using agnos, please consider telling me about your user experience here: https://github.com/krtab/agnos/issues/62.

