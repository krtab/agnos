[<img src="resources/red-iron.png" alt="drawing" width="365"/>](https://red-iron.eu/)

[![Crates.io badge](https://img.shields.io/crates/v/agnos?style=flat-square)](https://crates.io/crates/agnos)
[![github release badge badge](https://img.shields.io/github/v/release/krtab/agnos?style=flat-square)](https://github.com/krtab/agnos/releases/latest)
![github downloads badge](https://img.shields.io/github/downloads/krtab/agnos/total?style=flat-square)

Agnos
=====

<!-- TOC -->

- [Agnos](#agnos)
    - [Presentation](#presentation)
        - [Why](#why)
        - [How](#how)
    - [Installation](#installation)
        - [Released binary](#released-binary)
        - [AUR package](#aur-package)
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
    - [Developpers](#developpers)

<!-- /TOC -->

## Presentation

Agnos is a single-binary program allowing you to easily obtain certificates (including wildcards) from [Let's Encrypt](https://letsencrypt.org/) using [DNS-01](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge) challenges. It answers Let's Encrypt DNS queries on its own, bypassing the need for API calls to your DNS provider.

### Why


DNS-01 is summarized by Let's Encrypt documentation as such:

> <!-- TOC ignore:true -->
> #### Pros
>
> - You can use this challenge to issue certificates containing wildcard domain names.
> - It works well even if you have multiple web servers.
>
> <!-- TOC ignore:true -->
> #### Cons
>
> - Keeping API credentials on your web server is risky.
> - Your DNS provider might not offer an API.
> - Your DNS API may not provide information on propagation times.

By serving its own DNS answers, agnos:

- Nullify the need for API and API credentials
- Nullify all concerns regarding propagation times

Hence, **agnos removes virtually all downsides of dns-01 challenges**.

### How


Agnos leverages let's encrypt capability to follow DNS `NS` records. It requires you to add to your DNS zone:

1. An `A` (or `AAAA`) record pointing to the public facing IP address of the server on which agnos will run. On this server, UDP port 53 (the one used by DNS) should be open and free.
2. For each domain you will want to validate, a `NS` record for the corresponding `_acme-challenge` sub-domain, indicating that agnos should be used as a name server for this specific domain.

## Installation

This instructions are given for a Linux system but a similar process will likely work on all Unixes, and maybe windows.

### Released binary

Pre-compiled binaries for (relatively recent) Linux/amd64 are available for every tagged [release](https://github.com/krtab/agnos/releases).

### AUR package

Agnos is available in the [AUR](https://aur.archlinux.org/packages/agnos). You can install it using: `yay -S agnos`. 

### Building

Agnos is written in Rust. To build it you will need to have the rust toolchain installed. 

Once you have obtained the source, the following command will build the binary and put it in the root directory of the repo.

```bash
cd agnos/
cargo build --release
mv target/release/agnos agnos
```

### Setting capabilities to not run agnos as root

Because agnos listen on the low-numbered port 53, it requires special privileges. Running it as root will do, but if you (understandably) don't want to do that, the following command is for you:

```bash
# as root
setcap 'cap_net_bind_service=+ep' agnos
# agnos is the file of the binary as compiled above
```

## Usage

### Let's Encrypt accounts

Let's Encrypt accounts are identified by an e-mail address and a private RSA key. To generate such a key use the following command:

```shell
openssl genrsa 2048 > /path/to/store/the/key.pem
```

or if you prefer a larger key:

```shell
openssl genrsa 4096 > /path/to/store/the/key.pem
```

### Agnos configuration

Agnos is configured via a single [TOML](https://toml.io/) file. A commented example is available in [config_example.toml](https://github.com/krtab/agnos/blob/main/config_example.toml).

It is advised to use absolute rather than relative paths in the configuration file.

There are three "levels" in the configuration:

#### 1. General

The general configuration level is where the IP address to listen on is provided.

```toml
dns_listen_adr = "1.2.3.4:53"
```

#### 2. Accounts

Several Let's Encrypt accounts can be specified. For each account, an e-mail address and the path to the account RSA private key must be provided.

```toml
[[accounts]]
email= "contact@doma.in"
private_key_path = "priv_key.pem"
```

#### 3. Certificates

For each account, several certificates can be ordered. Each certificate can cover multiple domains. On disk, a certificate is represented by two files: the full certificate chain, and the private key of the certificate (generated by agnos and different from the account private key).

```toml
[[accounts.certificates]]
domains =  ["doma.in","*.doma.in"]
fullchain_output_file = "fullchain_A.pem"
key_output_file = "cert_key_A.pem"
```

### Configuration of your DNS provider

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

Let's assume that agnos is going to run on a server whose public facing IP address is `1.2.3.4`. The goal is to indicate that the three `_acme_challenge` domains cited above are managed by agnos using `NS` DNS records. `NS` records usually point to domain names, so we will also set an `A` record on `agnos-ns.doma.in` to point to `1.2.3.4` (here `agnos-ns.doma.in` is entirely arbitrary, it could be another, completely independent domain, you control, like `my-agnos.com`).

We create the following records:

In the zone of `doma.in`
```
agnos-ns.doma.in            A       1.2.3.4
_acme-challenge.doma.in     NS      agnos-ns.doma.in
```

In the zone of `examp.le`
```
_acme-challenge.examp.le            NS      agnos-ns.doma.in
_acme-challenge.another.examp.le    NS      agnos-ns.doma.in
```

**Note:** Though it may seem cumbersome, this must only be done once from your DNS provider web interface. Once it is done, you will never have to touch a `TXT` record.

### Running agnos

`agnos` takes a single command line argument, the path to its configuration file, and two optional flags: `--no-staging` to use Let's Encrypt production server, and `--debug` to display more debug information. Help is available via `agnos --help`.

When running, it checks whether the certificates of the full chain are going to expire in the next 30 days, and only renew them in that case, so it is suitable to be used in a cron job.

## Developpers

PRs and issues are very welcome.

Build using usual `cargo` commands.

The Makefile is for integration testing in a docker compose. At the root, run `sudo make` (sudo is required to use docker) to test agnos using pebble.