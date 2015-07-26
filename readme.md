DNS Foo
=======

DNS Sources
-----------
* DHCPv4 answers
	* from dhclient lease files
	* notification via kqueue on lease file inodes
* DHCPv6 answers
	* no lease files, at least for wide-dhcpv6
	* call a script from wide-dhcp6c to write nameservers to a socket?
* Router advertisements
	* Get advertisement packets from BPF socket
	* (re)-check if interface is configured for RA accept

Design
------
* Multiple processes:
	* Event loop (one per source/device?)
	* Information source parser, short lived, spawned on demand by event loops
		* tame()'d
	* Configuration repository
		* merge (conflicting) information from multiple sources
	* Unbound updater
		* calls unbound-control forward <ns1> <ns2> ...
* Use imsg_compose(3) for communication
