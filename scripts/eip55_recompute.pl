#!/usr/bin/env perl
use strict; use warnings;
use Digest::Keccak qw(keccak_256_hex);

my $addr = shift @ARGV;
if (!defined $addr) {
  print STDERR "usage: eip55_recompute.pl 0x<hexaddr>\n";
  exit 2;
}

$addr =~ s/^0x//i;
my $lc = lc($addr);
my $h = keccak_256_hex($lc);
my $out = '';
for my $i (0..39) {
  my $c = substr($lc, $i, 1);
  my $d = hex(substr($h, $i, 1));
  if ($c =~ /[a-f]/ && $d >= 8) { $out .= uc($c) } else { $out .= $c }
}
print "0x$out\n";

