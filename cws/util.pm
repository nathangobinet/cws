package cws::util;

use strict;
use warnings;
use utf8;
use v5.10;
use Data::Dumper;

use MIME::Base64;
use File::Copy "cp";
use File::Path qw(make_path);
use File::Temp qw/ tempfile /;
use IPC::Open3;
use Sys::Syslog qw(:standard :macros);
use IPC::Cmd qw[run_forked];
  
sub apply_template($$$) {
  my ($template_file, $output_file, $replace) = @_;
  my $rc = undef;

  $rc = open my $template_fh, '<', $template_file;
  unless ($rc) {
    return;
  }

  $rc = open my $output_fh, '>', $output_file;
  unless ($rc) {
    return;
  }

  while (my $line = <$template_fh>) {
    for my $key (keys %$replace) {
      my $replace_value = $replace->{$key};
      $line =~ s/%%$key%%/$replace_value/g;
    }
    $rc = print $output_fh $line;
    unless ($rc) {
      return;
    }
  }

  close $output_fh;
  close $template_fh;

  return 1;
}

sub load_file($$) {
  (my $file, my $logger) = @_;
  my $rc = undef;

  $rc = open (my $file_fh, '<', $file);
  unless ($rc) {
    $logger->error('failed to open file:`'.$file.q(').q(:).$!);
    return;
  }

  my $output = '';
  my $readed = 0;
  while ($readed = read ($file_fh, my $buf, 4*1024*1024)) { 
    $output .= $buf;
  }

  unless (defined ($readed)) {
    $logger->error('Error while reading file `'.$file.q(').q(:).$!);
    close ($file_fh);
    return;
  }

  close ($file_fh);
  return $output;
}

sub load_file_as_base64($$) {
  (my $file, my $logger) = @_;
  my $rc = undef;

  $rc = open (my $file_fh, '<', $file);
  unless ($rc) {
    $logger->error('failed to open file:`'.$file.q(').q(:).$!);
    return;
  }

  my $output = '';
  my $readed = 0;
  while ($readed = read ($file_fh, my $buf, 60*57)) {
    my $base64 = encode_base64($buf);
    $base64 =~ tr/\n//d; 
    $output .= $base64;
  }

  unless (defined ($readed)) {
    $logger->error('Error while reading file `'.$file.q(').q(:).$!);
    close ($file_fh);
    return;
  }

  close ($file_fh);
  return $output;
}

sub check_required_arguments($$) {
  (my $q, my $required_args) = @_;

  for my $arg (@$required_args) {
    my $value = $q->{param}($arg);
    unless (defined ($value)) {
      return;
    }
  }

  return 1;
}

sub override_with_arguments($$$) {
  (my $hash, my $q, my $args) = @_;

  for my $arg (@$args) {
    my $value = $q->{param}($arg);
    if (defined ($value)) {
      $hash->{$arg} = $value;
    }
  }

  return $hash;
}

# Read CA name from issuer data, and verify if certificate was signed by this ca
# 1) Extract CA name from issuer data, and then verify that CA exists.
# 2) Save certificate in temp file
# 3) Use openssl to verify that certificate is signed with CA
sub _get_issuer_ca_from_certificate($$$$) {
  (my $cert, my $issuer, my $auth, my $logger) = @_;
  my $rc = undef;

  my $openssl_binary = $cws::conf->{'path'}->{'ssl'};
  my $ca_name = undef;
  my $cert_name = undef;
  $cert =~ s/\t//gm;

  # 1)

  unless (defined($issuer) and defined($auth)) {
    $logger->err('_get_issuer_ca_from_certificate: Missing issuer or/and subject information for client certificate');
    return;
  }

  if ($issuer =~ m#CN=(?<ca_name>[^/,]+)#) {
    $ca_name = $+{'ca_name'};
  }

  unless ($ca_name) {
    $logger->warning('_get_issuer_ca_from_certificate: ca_name not found in issuer:`'.$issuer.q('));
    goto fail_read_cn;
    return;
  }

  if ($auth =~ m#CN=(?<cert_name>[^/,]+)#) {
    $cert_name = $+{'cert_name'};
  }

  unless ($cert_name) {
    $logger->warning('_get_issuer_ca_from_certificate: cert_name not found in auth:`'.$auth.q('));
    goto fail_read_cn;
    return;
  }

  my $ca_directory = $cws::conf->{'path'}->{'ca'}.q(/).$ca_name;

  unless (-d $ca_directory) {
    $logger->err('_get_issuer_ca_from_certificate: ca directory `'.$ca_directory.'\' is missing');
    goto fail_pre_verify;
  }

  my $crl_file = $ca_directory.q(/).$ca_name.'_crl.pem';
  unless (-s $crl_file) {
    $logger->err('_get_issuer_ca_from_certificate: `'.$crl_file.'\' is missing');
    goto fail_pre_verify;
  }

  my $ca_file = $ca_directory.q(/).$ca_name.'.crt';
  unless (-s $ca_file) {
    $logger->err('_get_issuer_ca_from_certificate: `'.$ca_file.'\' is missing');
    goto fail_pre_verify;
  }

  # 2)

  (my $tmp_fh, my $tmp_file) = tempfile();

  unless ($tmp_fh) {
    $logger->err('Failed to create temp file: '.$!);
    return;
  }

  print $tmp_fh $cert;
  close $tmp_fh;

  # 3)

  my @openssl_verify_cert = ($openssl_binary
                            ,'verify'
                            ,'-CRLfile',$crl_file
                            ,'-crl_check'
                            ,'-CAfile',$ca_file
                            ,$tmp_file);
  $rc = system (@openssl_verify_cert);
  if ($rc) {
    $logger->warning('_get_issuer_ca_from_certificate: Failed to verify certificate with openssl cmd: issuer=`'.$issuer.'\' `'.$crl_file.'\' `'.$ca_file.'\'');
    goto fail_verify;
  }

  unlink $tmp_file;

  return ($ca_name, $cert_name);

fail_verify:
  unlink $tmp_file;
fail_create_tmp:
fail_pre_verify:
fail_read_cn:
  return;
}

sub system_log($@)
{
  (my $logger, my @cmd) = @_;
  my $cmd = (join  ' ', @cmd);

  $logger->open_logfile();
  $logger->info('Running: '.$cmd);
  my $result = run_forked( $cmd, { timeout => 120 } );
  if (exists $logger->{'logger_fh'} and defined($logger->{'logger_fh'})) {
    my $fh = $logger->{'logger_fh'};
    print $fh 'ERR:'.$result->{'stderr'};
  }

  if ( $result->{'exit_code'} ) {
    $logger->info( $cmd.':'.$result->{'stdout'} );
    $logger->err( $cmd.':'.$result->{'stderr'} );
  }

  return $result->{'exit_code'};
}
1;
