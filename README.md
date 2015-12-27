# garden-gnome

This is a node.js application for redirecting *only* OS "does this device have internet" probes to an information portal.
It mimics the functionality of a "captive portal" without blocking/redirecting background traffic and traffic that is going to non-probe urls.

## Installation

System dependencies

* dnsmasq

```
sudo apt-get install dnsmasq
```

* netfilter
- Pretty much guaranteed to be present in linux.

Install node.js packages:

```
npm install
```

### Permissions

garden-gnome uses netfilter to add and remove iptables rules. In order to do that, it must have the proper permissions.

From https://github.com/diosney/node-netfilter/blob/master/README.md#requirements:

To properly execute the provided methods the application that uses the module must have the proper `sudo` privileges. 
One way to do it could be by adding a custom user to the system:

`sudo adduser --no-create-home garden-gnome`

then add its permissions at `/etc/sudoers` file:

`garden-gnome ALL= NOPASSWD: /sbin/iptables, /sbin/ip6tables, /sbin/ipset`

garden-gnome also must write to `/etc/dnsmasq.d/garden-gnome.conf` (or a config filename of your choosing). 
`/etc/dnsmasq.d` has root permissions, so as a root level user you must create a `/etc/dnsmasq.d/garden-gnome.conf` file with 
`garden-gnome` (or your user for running the portal) as the owner.

## Settings

Copy and tweak settings file

```
cp settings.js.example settings.js
```

## Usage

```
Usage: ./index.js

Options:
  --ip: Proxy listen IP address (default: 127.0.0.1)
  --port: Proxy listen port (default: 5080)
  --portalTime: Amount of time before showing portal again (in min) (default: 1440).
  --dnsLookupPeriod: Amount of time before refreshing dns cache. (in sec) (default: 300).
  --inInterface: Interface to redirect from (default: all).
```

Defaults and other settings can be overwritten in the settings.js file.

You likely want to daemonize this. TODO: Add info about systemd or others?


## Details

garden-gnome captures internet detection probes to the following urls:

* apple.com/library/test/success.html
* captive.apple.com/library/test/success.html
* www.ibook.info/library/test/success.html
* www.itools.info/library/test/success.html
* www.airport.us/library/test/success.html
* www.thinkdifferent.us/library/test/success.html
* www.appleiphonecell.com/library/test/success.html
* clients3.google.com/generate_204

and redirects them to our portal web page. On the portal page, taking an action (clicking on a link), will prevent that user from seeing the portal again
until a specified amount of time passes.

All other traffic will be ignored. This is all traffic except traffic on port 80 to the hosts shown above.


## License

GPLv3

Copyright 2015 Maxb
