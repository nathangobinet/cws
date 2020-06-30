#! /bin/perl
use strict;
use warnings;
use v5.10;
use utf8;
use Data::Dumper;

use File::Copy;
use File::Path qw(make_path);

my $install_path = '/etc/cws';

my $certificates_path = '/etc/ssl';
my $server_crt = $certificates_path.'/cws.crt';
my $server_key = $certificates_path.'/private/cws.key';
my $server_csr = $certificates_path.'/private/cws.csr';
my $server_dh = $certificates_path.'/cws.dhparam';

sub generate_self_signe_certificate($$) {
  (my $bits, my $days) = @_;
  my $rc = undef;

  $rc = system('openssl','genrsa','-out',$server_key,$bits);
  if ($rc) {
    goto fail_gen_key;
  }
  $rc = system('openssl','req','-new','-key',$server_key,'-out',$server_csr);
  if ($rc) {
    goto fail_gen_csr;
  }
  $rc = system('openssl','x509','-sha256','-req','-days',$days,'-in',$server_csr,'-signkey',$server_key,'-out',$server_crt);
  if ($rc) {
    goto fail_gen_crt;
  }
  $rc = system('openssl','dhparam','-out',$server_dh,4096);
  if ($rc) {
    goto fail_gen_dh;
  }
  unlink $server_csr;

  return 1;
fail_gen_dh:
  unlink $server_csr;
fail_gen_crt:
  unlink $server_crt;
fail_gen_csr:
  unlink $server_csr;
fail_gen_key:
  unlink $server_key;
  return;
}

sub install_cert() {
  my $rc = undef;

  print 'Do you want to generate a new certificate for cws ? [Y/n] ';
  my $answer = <STDIN>;
  unless (defined ($answer)) {
    say 'Action canceled';
    return;
  }

  chomp $answer;

  if ($answer eq 'n' || $answer eq 'N') {
    unless (-s $server_crt and -s $server_key) {
      say 'You must provide the following files:';
      say ' - a certificate at: '.$server_crt;
      say ' - a private key at: '.$server_key;
      return;
    } else {
      say 'Certificates found';
    }
  } else {
    if (-s $server_crt or -s $server_key) {
      say 'Certificates found :'.$server_crt.' or '.$server_key;
      return;
    }
    say 'Generating certificate..';
    $rc = generate_self_signe_certificate(2048, 365);
    unless ($rc) {
      return;
    }
    say 'Certificate generated in: '.$certificates_path;
  }
  return 1;
}

if ( defined $ARGV[0] ) {
  $install_path = $ARGV[0];
}

if ( -s './conf/global.conf' ) {
  unless ( -d $install_path ) {
    make_path($install_path) or die "make path $install_path failed: $!";
  }
  copy('./conf/global.conf', $install_path.'/global.conf') or die "Copy failed: $!";
  say 'you may want to cp ./conf/radius-ext.conf $install_path';
  unless ( -d $install_path.'/ca' ) { 
    make_path( $install_path.'/ca',{ owner=>'www-data', mode=>0700 }) or
      die "make path $install_path/ca failed: $!";
  }
  system('cp', '-r', './template', $install_path) and die "Copy failed: $!";
} else {
  die 'please launch where the README is';
}

unless (install_cert()) {
  exit 1;
}

say 'please link ./conf/root.nginx to a sites-enabled nginx directory';
