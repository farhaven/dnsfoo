DNS Foo
=======

This is a simple(-ish) program that watches `dhclient` lease files and IPv6
router advertisements for DNS information and either calls `unbound-control
forward <ns1> <ns2> <ns3>` to update unbounds default forward zone with the
servers it found or rewrites `/etc/rebound.conf` and sends a HUP signal to
rebound to update its configuration.

Building
--------
If you're running a recent OpenBSD -current which has the `pledge()` system
call, a simple `make` should do the trick. If your system does not support
`pledge()`, you can simply comment out all calls to it.

`dnsfoo` requires a few things that are specific to OpenBSD, such as the `imsg`
interface. If you port over `libutil`, it shouldn't be too hard to get working.
You need a system which provides IPv6 raw sockets.

Configuration
-------------
Configuration information is taken from `dnsfoo.conf` in the current directory.
This is an example:

    user "_dhcp"
    server unbound

    device "trunk0" {
        dhcpv4 "/var/db/dhclient.leases.trunk0"
        dhcpv4 "/tmp/dnslease"
        rtadv
    }

`device` statements group DNS information sources for conflict resolution. You
can use more than one source statement if you want. `user` specifies the user
to drop priviledges to. This user must be able to control unbound with
`unbound-control`. The default is `_dhcp`.

If you are using `rebound` instead of unbound, you can add a `server rebound`
statement to your configuration file. The default is unbound.

Usage
-----
Set up unbound so that it can be used as a local resolver and so that
`unbound-control` can be used. I use something like this as my configuration
file:

    server:
        interface: 127.0.0.1
        interface: ::1

        access-control: 0.0.0.0/0 refuse
        access-control: 127.0.0.0/8 allow
        access-control: ::0/0 refuse
        access-control: ::1 allow

        hide-identity: no
        hide-version: no

    remote-control:
        control-enable: yes

    forward-zone:
        # Some default servers to get us started. These will be replaced by
        # dnsfoo
        name: "."                # use for ALL queries
        forward-addr: 74.82.42.42        # he.net
        forward-addr: 2001:470:20::2        # he.net v6
        forward-first: no    # try direct if forwarder fails

Then set up your system so that it uses unbound as the default resolver. This is
my `/etc/resolv.conf`:

    nameserver ::1
    lookup file bind

Run `dnsfoo`:

    $ doas ./dnsfoo
    rtadv: len: 96 from fe80::203:2dff:fe20:cf85
                RDNSS len=40 hdr=8 lifetime=3600
    got unbound update data: "2001:470:7193:6::1,2001:470:7193:10::1"

And observe unbounds forwarders:

    $ unbound-control forward
    2001:470:7193:10::1 2001:470:7193:6::1

Notes / Missing Stuff
---------------------
### DNS Sources
* DHCPv6 answers
	* no lease files, at least for wide-dhcpv6
	* call a script from wide-dhcp6c to write nameservers to a socket?

### Handling of DNS from multiple sources
* What do we do if we go from a network that has RDNSS to one that doesn't?
	* The DNS info from the RDNSS network won't be overwritten
	* We can't use "lost the default route" as a signal to flush the list of DNS
	  (might come _after_ the new nameservers came in)
