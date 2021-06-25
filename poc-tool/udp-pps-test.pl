#!/usr/bin/perl

# helper script to calculate the number of potential XIDs for a complete day
#
# 15 pids
# a complete day (86400 seconds)
# Number of potential xids: 86415 (due to the overlaps)
#
# Accoring to the measurement of this script, 
# the smallest F VM instance is capable of sending ~174784 packets per second
#
# Conclusion: we can test at least 2 days in one DHCP window!

use strict;
use warnings;
use IO::Socket::INET;


my $sock = IO::Socket::INET->new(
    Proto    => 'udp',
    PeerPort => 5000,
    PeerAddr => '10.128.0.5',
) or die "Could not create socket: $!\n";

my $counter = 0;
eval {
   local $SIG{ALRM} = sub { die "alarm\n" };
   alarm 10;
   while(1) {
      $sock->send(('x' x 150)) or die "Send error: $!\n";
      $counter++;
   }
   alarm 0;
};

print "packets sent: $counter ($@)\n";
