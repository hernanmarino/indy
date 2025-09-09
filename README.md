![Indy: the ultimate recovery tool](readme/header.png)

## About

Recovering funds from a wallet using just the mnemonic phrase has historically been a difficult problem. The main reason being that different wallets use different derivation paths and script types. Sadly, the mnemonic format doesn't document this and other important metadata needed during the recovery process.

Indy intends to cover the gap left by the standard by making the recovery of funds from a mnemonic trivial. Just input your mnemonic and let the tool guess the derivation path used by the wallet.

You can use Indy to sweep all the funds to a destination address of your choice.

## Features

* Supports sweeping funds from mnemonics and xprivs (an xpub is read, but every derivation path
  known here starts at a hardened level, which a public key cannot derive)
* Supports mnemonics in Chinese, Czech, English, French, Italian, Japanese, Korean,
  Portuguese, Russian, Spanish and Turkish
* Supports all the derivation paths and address types from the wallets listed in [walletsrecovery.org](https://walletsrecovery.org/)
* Supports customizing the address gap limit and the account gap limit
* Supports using a custom electrum server

## Demo

![](readme/demo.gif)

## How it works

Indy uses electrum servers to try [every possible combination](https://github.com/esneider/indy/blob/master/descriptors.py#L10) of known derivation paths and script types. Once the relevant path and script type combinations are detected, the tool will proceed to find all the UTXOs for those combinations. After all funds are found, if you desire so, Indy can create a transaction that will sweep them to an address of your choosing.

Some wallets use a custom address gap limit (or none at all), or really high account numbers, so you can choose to override these parameters.

Finally, notice that this tool is only useful for single key wallets. If you are using a multisig or lightning wallet, then you cannot recover the funds with just the mnemonic.

## Installation
```
git clone https://github.com/esneider/indy && cd indy
pip3 install -r requirements.txt
python3 indy.py --help
```

Every dependency is pinned to a version and to the hashes of the files it is made of, so pip
turns down a file that does not match what is written down. Except on 32 and 64 bit Windows,
one of them is compiled while installing: that needs a C toolchain, and it fetches its C
library over the network as it builds.

## Usage

The key is asked for out of sight when it is left off the command line, so that it stays out of
your shell history and out of `ps`. Use `--ask-passphrase` to be asked for the passphrase the
same way.

```
usage: indy.py [-h] [--passphrase <pass> | --ask-passphrase]
               [--allow-invalid-checksum] [--address <address>] [--broadcast]
               [--fee-rate <rate>] [--allow-high-fee] [--yes]
               [--address-gap <num>] [--account-gap <num>] [--host <host>]
               [--port <port>] [--protocol {t,s}] [--no-batching] [--insecure]
               [key]

Find and sweep all the funds from a mnemonic or bitcoin key, regardless of the
derivation path or address format used.

positional arguments:
  key                   master key to sweep, formats: mnemonic, xpriv or xpub
                        (asked for out of sight if left off)

options:
  -h, --help            show this help message and exit
  --passphrase <pass>   optional secret phrase necessary to decode the
                        mnemonic
  --ask-passphrase      ask for the passphrase out of sight instead of reading
                        it here
  --allow-invalid-checksum
                        derive from a mnemonic whose BIP39 checksum does not
                        match

sweep transaction:
  --address <address>   craft a transaction sending all funds to this address
  --broadcast           if present broadcast the transaction to the network
  --fee-rate <rate>     fee rate to use in sat/vbyte (default: next block fee)
  --allow-high-fee      allow a fee above 10% of the funds found
  --yes                 broadcast without asking for confirmation

scanning parameters:
  --address-gap <num>   max empty addresses gap to explore (default: 20)
  --account-gap <num>   max empty account levels gap to explore (default: 0)

electrum server:
  --host <host>         hostname of the electrum server to use
  --port <port>         port number of the electrum server to use
  --protocol {t,s}      electrum connection protocol: t=TCP, s=SSL (default:
                        s)
  --no-batching         disable request batching
  --insecure            connect without verifying the server certificate, and
                        allow plain TCP
```

## Tests

```
python3 -m unittest discover
```

## Credits

This tool was created after reading [this twitter thread](https://twitter.com/aantonop/status/1259478489427775491) by [@aantonop](https://twitter.com/aantonop). Many thanks for the idea and the relentless contributions to the Bitcoin community!

Also, Indy stands on the tremendous effort done by [@NVK](https://twitter.com/NVK) and [@J9Roem](https://twitter.com/J9Roem) documenting the derivation paths for many wallets at [walletsrecovery.org](https://walletsrecovery.org/). It belongs in a museum!
