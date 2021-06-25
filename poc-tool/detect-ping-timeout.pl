#!/usr/bin/perl

use strict;
use warnings;
use Net::Ping;

$| = 1;

my $host = shift @ARGV;
die "Usage: $0 target-ip-address\n" if(!$host);

print "\n";

my $p = Net::Ping->new("icmp", $ENV{PING_TIMEOUT} || 0.3);
my $now;
while(1) {
   $now = time();
   last if(!$p->ping($host));
   print "\r$host: alive: $now";
}
$p->close();

print "\n";
print "$host seems to be not alive anymore\n";

exit(0);
