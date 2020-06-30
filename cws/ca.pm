package cws::ca;
use utf8;
use strict;
use warnings;
use Data::Dumper;
use v5.10;

use cws;
use cws::util;
use File::Copy "cp";
use File::Path qw(make_path);
use File::Temp qw/ tempfile /;
use MIME::Base64;

###
# CA tool
##

sub _load_openssl_conf($$) {
  (my $file, my $logger) = @_;
  my $rc = undef;

  $rc = open my $file_fh, '<', $file;
  unless ($rc) {
    $logger->error('Failed to read openssl configuration file for loading it: `'.$file.q(').': '.$!);
    return;
  }

  my $openssl_conf = {};
  while (my $line = <$file_fh>) {
    if ($line =~ /^dir\s*=\s*(?<dir_ca>.+)$/) {
      $openssl_conf->{'dir_ca'} = $+{'dir_ca'};
    }
    elsif ($line =~ /^private_key\s*=\s*\?dir\/(?<ca_name>.+)$/) {
      $openssl_conf->{'ca_name'} = $+{'ca_name'};
    }
    elsif ($line =~ /^C\s*=\s*(?<code_country>.+)$/) {
      $openssl_conf->{'code_country'} = $+{'code_country'};
    }
    elsif ($line =~ /^ST\s*=\s*(?<state>.+)$/) {
      $openssl_conf->{'state'} = $+{'state'};
    }
    elsif ($line =~ /^L\s*=\s*(?<city>.+)$/) {
      $openssl_conf->{'city'} = $+{'city'};
    }
    elsif ($line =~ /^O\s*=\s*(?<organisation>.+)$/) {
      $openssl_conf->{'organisation'} = $+{'organisation'};
    }
    elsif ($line =~ /^OU\s*=\s*(?<organisation_unit>.+)$/) {
      $openssl_conf->{'organisation_unit'} = $+{'organisation_unit'};
    }
    elsif ($line =~ /^emailAddress\s*=\s*(?<email>.+)$/) {
      $openssl_conf->{'email'} = $+{'email'};
    }
    elsif ($line =~ /^default_bits\s*=\s*(?<key_length>.+)$/) {
      $openssl_conf->{'key_length'} = $+{'key_length'};
    }
    elsif ($line =~ /^default_days\s*=\s*(?<cert_valid_time>.+)$/) {
      $openssl_conf->{'cert_valid_time'} = $+{'cert_valid_time'};
    }
    elsif ($line =~ /^default_crl_days\s*=\s*(?<crldays>.+)$/) {
      $openssl_conf->{'crldays'} = $+{'crldays'};
    }
  }
  return $openssl_conf;
}

# Generate a new certificate signed by specified CA
# Optionaly it can be generated using a given CSR. If no csr are provided, it generate a key, then a csr
#
# This function generate the following files:
#  - $ca_directory/out/$certificate_name/$certificate_name.key
#  - $ca_directory/out/$certificate_name/$certificate_name.crt
#  - $ca_directory/out/$certificate_name/$certificate_name.pem
#  - $ca_directory/out/$certificate_name/$certificate_name.p12 (only if NO foreign csr are provided)
# Don't forget to clean this files
#
# 1) Create output directory
# 2) Create configuration file from CA configuration's and given information in $override_openssl_conf
# 3) If a csr is provided, then check it, else we create one
# 4) Create certificate using csr, and sign it with CA
# 5) Generate pem and p12 file
sub _create_crt($$$$$$$$) {
  (my $ca_name, my $name, my $override_openssl_conf, my $extensions, my $foreign_csr, my $foreign_csr_format, my $passwd, my $logger) = @_;
  my $rc = undef;

  my $ca_directory = $cws::conf->{'path'}->{'ca'}.q(/).$ca_name;
  my $output_directory = $ca_directory.'/out';
  my $cert_directory = $output_directory.q(/).$name;

  my $ca_key = $ca_directory.'/'.$ca_name.'.key';
  my $ca_cert = $ca_directory.'/'.$ca_name.'.crt';
  my $ca_openssl_conf_file = $ca_directory.'/confssl.conf';

  my $cert_key    = $cert_directory.q(/).$name.'.key';
  my $cert_csr    = $cert_directory.q(/).$name.'.csr';
  my $csr_format  = 'pem';
  my $cert_cert   = $cert_directory.q(/).$name.'.crt';
  my $cert_pkcs12 = $cert_directory.q(/).$name.'.p12';
  my $cert_pem    = $cert_directory.q(/).$name.'.pem';
  $cert_csr       = $foreign_csr if (defined ($foreign_csr));
  $csr_format     = $foreign_csr_format if (defined ($foreign_csr_format));

  my $openssl_binary = $cws::conf->{'path'}->{'ssl'};
  my $extensions_file = $cws::conf->{'path'}->{'extensions_file'};
  my $openssl_conf_file = $cert_directory.'/confssl.conf';
  my $pkcs12passwd = '';

  if (defined ($passwd)) {
    $pkcs12passwd = $passwd;
  }

  $logger->notice('Creating new certificate: `'.$name.q(').' for CA: `'.$ca_name.q('));

  $override_openssl_conf->{'common_name'} = $name;

  # 1)

  $rc = mkdir $cert_directory;
  unless ($rc) {
    $logger->error('Failed to create directory for certificate `'.$cert_directory.q(').': '.$!);
    goto fail_create_directory;
  }

  # 2)

  my $openssl_conf = _load_openssl_conf($ca_openssl_conf_file, $logger);
  unless ($openssl_conf) {
    $logger->error('Failed to load config from file: `'.$ca_openssl_conf_file.q('));
    goto fail_create_ssl_conf;
  }

  foreach my $key (keys %$override_openssl_conf) {
    $openssl_conf->{$key} = $override_openssl_conf->{$key};
  }

  my $template_file = $cws::conf->{'template'}->{'openssl_conf'};
  $rc = cws::util::apply_template($template_file, $openssl_conf_file, $openssl_conf);
  unless ($rc) {
    $logger->error('Failed to apply template for file: `'.$openssl_conf_file.q(').': '.$!);
    goto fail_create_ssl_conf;
  }

  # 3)

  if (-s $cert_csr) {
    my @openssl_check_csr_cmd = ($openssl_binary
                                ,'req'
                                ,'-in',$cert_csr
                                ,'-inform',$csr_format);
    if ($csr_format == 'der') {
      push @openssl_check_csr_cmd, '-out', $cert_csr, '-outform', 'pem';
    } else {
      push @openssl_check_csr_cmd, '-noout';
    }
    $rc = cws::util::system_log($logger, @openssl_check_csr_cmd);
    if ($rc) {
      $logger->error('Check provided csr failed `'.$cert_csr.q(').': '.$!);
      goto fail_create_csr;
    }
  } else {
    my @openssl_create_key_cmd = ($openssl_binary
                                 ,'genrsa'
                                 ,'-out',$cert_key
                                 ,$openssl_conf->{'key_length'});
    $rc = cws::util::system_log($logger, @openssl_create_key_cmd);
    if ($rc) {
      $logger->error('Failed to generate key');
      goto fail_create_csr;
    }

    my @openssl_create_csr_cmd = ($openssl_binary
                                 ,'req'
                                 ,'-batch'
                                 ,'-sha256'
                                 ,'-config',$openssl_conf_file
                                 ,'-new'
                                 ,'-key',$cert_key
                                 ,'-out',$cert_csr);
    $rc = cws::util::system_log($logger, @openssl_create_csr_cmd);
    if ($rc) {
      $logger->error('Failed to generate csr');
      goto fail_create_csr;
    }
  }

  # 4)

  my @openssl_create_crt_cmd = ($openssl_binary
                               ,'ca'
                               ,'-batch'
                               ,'-md','sha256'
                               ,'-config',$openssl_conf_file
                               ,'-cert',$ca_cert
                               ,'-keyfile',$ca_key
                               ,'-in',$cert_csr
                               ,'-out',$cert_cert);

  if (defined ($extensions)) {
    if ($extensions eq 'FreeRadius-Server') {
      push @openssl_create_crt_cmd, ('-extensions', 'xpserver_ext', '-extfile', $extensions_file);
    }
    elsif ($extensions eq 'FreeRadius-Client') {
      push @openssl_create_crt_cmd, ('-extensions', 'xpclient_ext', '-extfile', $extensions_file);
    }
  }

  $rc = cws::util::system_log($logger, @openssl_create_crt_cmd);
  if ($rc) {
    $logger->error('Failed to create crt: `'.$cert_cert.q('));
    goto fail_create_crt;
  }

  # 5)

  if (-s $cert_key) {
    my @openssl_create_p12_cmd = ($openssl_binary
                                 ,'pkcs12'
                                 ,'-export'
                                 ,'-password','pass:'.$pkcs12passwd
                                 ,'-in',$cert_cert
                                 ,'-inkey',$cert_key
                                 ,'-certfile',$ca_cert
                                 ,'-out',$cert_pkcs12);
    $rc = cws::util::system_log($logger, @openssl_create_p12_cmd);
    if ($rc) {
      $logger->error('Failed to create p12: `'.$cert_pem.q('));
      goto fail_create_pem;
    }

    my @openssl_create_pem_cmd = ($openssl_binary
                                 ,'pkcs12'
                                 ,'-nodes'
                                 ,'-passin','pass:'.$pkcs12passwd
                                 ,'-in',$cert_pkcs12
                                 ,'-out',$cert_pem);
    $rc = cws::util::system_log($logger, @openssl_create_pem_cmd);
    if ($rc) {
      $logger->error('Failed to create pem from p12: `'.$cert_pem.q('));
      goto fail_create_pem;
    }
  }
  else {
    my @openssl_create_p12_cmd = ($openssl_binary
                                 ,'pkcs12'
                                 ,'-export'
                                 ,'-password','pass:'.$pkcs12passwd
                                 ,'-in',$cert_cert
                                 ,'-nokeys'
                                 ,'-certfile',$ca_cert
                                 ,'-out',$cert_pkcs12);
    $rc = cws::util::system_log($logger, @openssl_create_p12_cmd);
    if ($rc) {
      $logger->error('Failed to create p12: `'.$cert_pem.q('));
      goto fail_create_pem;
    }

    my @openssl_create_pem_cmd = ($openssl_binary
                                 ,'x509'
                                 ,'-outform','PEM'
                                 ,'-in',$cert_cert
                                 ,'-out',$cert_pem);
    $rc = cws::util::system_log($logger, @openssl_create_pem_cmd);
    if ($rc) {
      $logger->error('Failed to create pem: `'.$cert_pem.q('));
      goto fail_create_pem;
    }
  }

  unlink $cert_csr;
  unlink $openssl_conf_file;

  return 1;
fail_create_pem:
  unlink $cert_pem;
  unlink $cert_pkcs12;
  #FIXME revoke cert
fail_create_crt:
  unlink $cert_cert;
fail_create_csr:
  unlink $cert_key;
  unlink $cert_csr;
fail_create_ssl_conf:
  unlink $openssl_conf_file;
fail_create_directory:
  rmdir $cert_directory;
  return;
}

sub _is_cert_exists($$$) {
  (my $ca_name, my $name, my $logger) = @_;
  my $rc = undef;

  my $ca_directory = $cws::conf->{'path'}->{'ca'}.q(/).$ca_name;
  my $index_file = $ca_directory.'/index.txt';

  $rc = open my $index_fh, '<', $index_file;
  unless ($rc) {
    $logger->error('_is_cert_exists: Failed to open index file: `'.$index_file.'\': '.$!);
    return;
  }

  my $serial_number = undef;
  while (my $line = <$index_fh>) {
    if ($line =~ m#^V\s+\w+\s+(?<serial>\w+)\s+\w+\s+/(?:\w+=\w+/)+CN=$name$#) {
      $serial_number = $+{'serial'};
      last;
    }
  }
  close $index_fh;

  if (defined ($serial_number)) {
    return 1;
  }
  return 0;
}

sub _get_certificate_file($$$)
{
  (my $ca_name, my $name, my $logger) = @_;
  my $rc = undef;

  my $ca_directory = $cws::conf->{'path'}->{'ca'}.q(/).$ca_name;
  my $index_file = $ca_directory.'/index.txt';

  $rc = open my $index_fh, '<', $index_file;
  unless ($rc) {
    $logger->error('Failed to open index file: `'.$index_file.q(').q(:).$!);
    return;
  }

  my $serial_number = undef;
  while (my $line = <$index_fh>) {
    if ($line =~ m#^V\s+\w+\s+(?<serial>\w+)\s+\w+\s+/(?:\w+=\w+/)+CN=$name$#) {
      $serial_number = $+{'serial'};
      last;
    }
  }
  close $index_fh;

  unless ($serial_number) {
    $logger->warning('Certificate `'.$name.'\' not found in index file:`'.$index_file.q('));
    return;
  }

  my $cert_file = $ca_directory.q(/).$serial_number.'.pem';
  unless (-s $cert_file) {
    $logger->error('Missing certificate file `'.$cert_file.q('));
    return;
  }
  return $cert_file;
}

# Revoke a certificate
sub _revoke_certificate($$$) {
  (my $ca_name, my $name, my $logger) = @_;
  my $rc = undef;

  my $ca_directory = $cws::conf->{'path'}->{'ca'}.q(/).$ca_name;

  my $ca_key = $ca_directory.'/'.$ca_name.'.key';
  my $ca_cert = $ca_directory.'/'.$ca_name.'.crt';
  my $ca_openssl_conf_file = $ca_directory.'/confssl.conf';

  my $cert_file = _get_certificate_file($ca_name, $name, $logger);
  my $openssl_binary = $cws::conf->{'path'}->{'ssl'};

  unless ($cert_file) {
    $logger->error('certificate file not found, this certificate does not exists or is already revocked');
    return;
  }

  unless (-s $cert_file) {
    $logger->error('missing cert file:'.$cert_file);
    return;
  }

  my @openssl_revoke_certificate_cmd = ($openssl_binary
                                      ,'ca'
                                      ,'-revoke',$cert_file
                                      ,'-config',$ca_openssl_conf_file
                                      ,'-keyfile',$ca_key
                                      ,'-cert',$ca_cert);

  $rc = cws::util::system_log($logger, @openssl_revoke_certificate_cmd);
  if ($rc) {
    $logger->error('Failed to revoke certificate:'.$cert_file);
    return;
  }

  $rc = cws::root::_update_crl($ca_name, $logger, 1);
  unless ($rc) {
    $logger->error('Failed to update crl for '.$ca_name);
    return;
  }

  $rc = cws::root::_remove_admin($ca_name, $name, $logger);
  unless ($rc) {
    $logger->error('Failed to remove certificate `'.$name.'\' from admin list');
    return;
  }
  return 1;
}

# Read given csr file with openssl, and then read the CN from it and return it.
sub _load_commomn_name_from_csr($$$)
{
  (my $csr_file, my $csr_format, my $logger) = @_;
  my $rc = undef;

  my $openssl_binary = $cws::conf->{'path'}->{'ssl'};

  my @openssl_read_csr_cmd = ($openssl_binary
                             ,'req'
                             ,'-in',$csr_file
                             ,'-reqopt','ca_default'
                             ,'-inform',$csr_format
                             ,'-subject');

  $logger->info('Running: '.(join  ' ', @openssl_read_csr_cmd));

  $rc = open (my $csr_fh, '-|', @openssl_read_csr_cmd);
  unless ($rc) {
    $logger->error('Failed to run openssl to read csr:'.$!);
    return;
  }

  my $common_name = undef;
  while (my $line = <$csr_fh>) {
    chomp $line;
    if ($line =~ /CN=(?<cn>[^\/,]+)(?:\/|,|\Z)/) {
      $common_name = $+{'cn'};
      last;
    }
  }

  close $csr_fh;

  unless ($common_name) {
    if ($?) {
      $logger->error('Failed to read common name from given csr, error with openssl command, exit='.$?);
      $rc = cws::util::system_log($logger, @openssl_read_csr_cmd);
    } else {
      $logger->error('Failed to read common name from given csr');
    }
    return;
  }

  unless ($common_name =~ /\A[-\w\.]+\Z/) {
    $logger->error('Invalid common name: `'.$common_name.q('));
    return;
  }

  return $common_name;
}

sub _create_crt_with_csr($$$$$$$) {
  (my $ca_name, my $override_openssl_conf, my $extensions, my $csr, my $csr_format, my $passwd, my $logger) = @_;
  my $rc = undef;

  unless ($csr) {
    $logger->error('csr is empty');
    return;
  }

  (my $tmp_fh, my $tmp_file) = tempfile();

  unless ($tmp_fh) {
    $logger->error('Failed to create temp file: '.$!);
    return;
  }

  print $tmp_fh decode_base64($csr);
  close $tmp_fh;

  my $common_name = _load_commomn_name_from_csr($tmp_file, $csr_format, $logger);
  unless ($common_name) {
    unlink $tmp_file;
    return;
  }

  $rc = _is_cert_exists($ca_name, $common_name, $logger);
  unless (defined ($rc)) {
    unlink $tmp_file;
    $logger->error($ca_name.': Failed to chech if crt exists');
    return;
  }
  if ($rc) {
    unlink $tmp_file;
    $logger->warning($ca_name.': certificate with name `'.$common_name.'\' already exists');
    return;
  }

  $rc = _create_crt($ca_name, $common_name, $override_openssl_conf, $extensions, $tmp_file, $csr_format, $passwd, $logger);
  unless ($rc) {
    unlink $tmp_file;
    $logger->error($ca_name.': Failed to create crt');
    return;
  }

  unlink $tmp_file;
  return $common_name;
}

sub _create_crt_without_csr($$$$$$) {
  (my $ca_name, my $name, my $override_openssl_conf, my $extensions, my $passwd, my $logger) = @_;
  my $rc = undef;

  $rc = _create_crt($ca_name, $name, $override_openssl_conf, $extensions, undef, undef, $passwd, $logger);
  unless ($rc) {
    $logger->error('Failed to create crt');
    return;
  }

  return 1;
}

sub _get_and_delete_generated_cert($$$$) {
  (my $ca_name, my $name, my $format, my $logger) = @_;

  my $rc = undef;

  my $ca_directory = $cws::conf->{'path'}->{'ca'}.q(/).$ca_name;
  my $output_directory = $ca_directory.'/out';
  my $cert_directory = $output_directory.q(/).$name;

  my $cert_key    = $cert_directory.q(/).$name.'.key';
  my $cert_cert   = $cert_directory.q(/).$name.'.crt';
  my $cert_pkcs12 = $cert_directory.q(/).$name.'.p12';
  my $cert_pem    = $cert_directory.q(/).$name.'.pem';

  my $output = undef;

  my $send_key = 0;
  my $send_cert = 0;
  my $send_pkcs12 = 0;
  my $send_pem = 0;

  unless (defined ($format)) {
    $send_key = 1;
    $send_cert = 1;
    $send_pkcs12 = 1;
    $send_pem = 1;
  }
  elsif ($format eq 'pem') {
    $send_pem = 1;
  }
  elsif ($format eq 'pkcs12') {
    $send_pkcs12 = 1;
  }
  elsif ($format eq 'cert') {
    $send_cert = 1;
  }
  else {
    $logger->error('Invalid format: `'.$format.q('));
    return;
  }

  unless (-d $cert_directory) {
    $logger->error('certificate directory not found: `'.$cert_directory.q('));
    return;
  }

  unless (-s $cert_cert) {
    $logger->error('certificate cert is missing: `'.$cert_cert.q('));
    return;
  }

  unless (-s $cert_pem) {
    $logger->error('certificate pem is missing: `'.$cert_pem.q('));
    return;
  }

  $output = {};

  if ($send_key and -s $cert_key) {
    my $key = cws::util::load_file_as_base64($cert_key, $logger);
    unless ($key) {
      $logger->error('Failed to load key, not sending');
      $output->{'key'} = 'error';
    } else {
      $output->{'key'} = $key;
    }
  }
  else {
    $output->{'key'} = 'none';
  }

  if ($send_pkcs12 and -s $cert_pkcs12) {
    my $pkcs12 = cws::util::load_file_as_base64($cert_pkcs12, $logger);
    unless ($pkcs12) {
      $logger->error('Failed to load pkcs12, not sending');
      $output->{'pkcs12'} = 'error';
    } else {
      $output->{'pkcs12'} = $pkcs12;
    }
  }
  else {
    $output->{'pkcs12'} = 'none';
  }

  if ($send_cert) {
    my $cert = cws::util::load_file_as_base64($cert_cert, $logger);
    unless ($cert) {
      $logger->error('Failed to load cert, not sending');
      $output->{'cert'} = 'error';
    } else {
      $output->{'cert'} = $cert;
    }
  }
  else {
    $output->{'cert'} = 'none';
  }

  if ($send_pem) {
    my $pem = cws::util::load_file_as_base64($cert_pem, $logger);
    unless ($pem) {
      $logger->error('Failed to load pem, not sending');
      $output->{'pem'} = 'error';
    } else {
      $output->{'pem'} = $pem;
    }
  }
  else {
    $output->{'pem'} = 'none';
  }

  unlink $cert_key;
  unlink $cert_cert;
  unlink $cert_pkcs12;
  unlink $cert_pem;
  rmdir $cert_directory;

  return $output;
}


1;
