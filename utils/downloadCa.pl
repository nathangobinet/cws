#! /usr/bin/perl
use strict;
use warnings;
use utf8;
use v5.10;
use Data::Dumper;

use MIME::Base64;

if ($#ARGV eq -1) {
  warn 'Missing arguments: '.$0.' export_name';
}

my @valid_keys = ('cws','cert','pem','pkcs12','key','der');
my $result = {};
while (my $line = <STDIN>) {
  chomp $line;
  if ($line =~ /^(?<key>[\w-]+): (?<value>.*)$/) {
    my $key = lc $+{'key'};
    next unless ($key ~~ @valid_keys);
    my $value = $+{'value'};
    $value =~ s/\r$//;
    $result->{$key} = $value;
  }
}

my $name = $ARGV[0];

foreach my $key (keys %$result) {
  if ($result->{$key} eq 'none') {
    next;
  }
  if ($result->{$key} eq 'error') {
    warn 'error for '.$key.' from server';
    next;
  }
  my $rc = open my $file_fh, '>', $name.q(.).$key;
  unless ($rc) {
    warn 'Failed to open file :`'.$name.q(.).$key.q(').q(:).$!;
  }

  print $file_fh decode_base64($result->{$key});
  close $file_fh;
}

exit 0;
