#! /usr/bin/perl
use strict;
use warnings;
use Data::Dumper;
use Sys::Syslog qw(:standard :macros);
use cws;
use cws::root;
use v5.10;

use File::Temp qw/ tempfile /;

use tool::log;

unless (scalar @ARGV ge 2) {
  exit 1;
}

my $ca_name = $ARGV[0];
my $name = $ARGV[1];
my $logger = tool::log::init(7);

sub tool::log::open_logfile { }

my $ca_directory = $cws::conf->{'path'}->{'ca'}.q(/).$ca_name;

unless (-d $ca_directory) {
  warn 'CA not found';
  exit 2;
}

my $rc = cws::ca::_revoke_certificate($ca_name, $name, $logger);
unless ($rc) {
  exit 1;
}
exit 0;
