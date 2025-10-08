#!/usr/bin/env perl
use strict; use warnings;

my $ok = eval {
  require Digest::Keccak;
  Digest::Keccak->import('keccak_256_hex');
  1;
};

if ($ok) {
  print "ok\n";
  exit 0;
} else {
  exit 1;
}

