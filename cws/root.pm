package cws::root;

use strict;
use warnings;
use Data::Dumper;
use v5.10;

use cws;
use cws::util;
use cws::ca;

use File::Copy "cp";
use File::Path qw(make_path remove_tree);
use File::Temp qw/ tempfile /;

# ROOT provide code function, created CA must use CA api

###
# ROOT tool
##

# Create a new CA: generate a key and and self signed certificate
# 1) Create serial file
# 2) Create empty file index.txt file
# 3) Create openssl configuration file
# 4) Create key
# 5) Create csr
# 6) Generate crt, signed by key
# 7) Convert crt to der
# 8) Create output/ directory
# 9) CRL
sub _create_ca($$$$) {
  (my $ca_name, my $openssl_conf, my $logger, my $with_x509_extensions) = @_;
  my $rc = undef;

  my $ca_directory = $cws::conf->{'path'}->{'ca'}.q(/).$ca_name;
  my $ca_logfile = $ca_directory.'/log';
  my $ca_key = $ca_directory.'/'.$ca_name.'.key';
  my $ca_csr = $ca_directory.'/'.$ca_name.'.csr';
  my $ca_cert = $ca_directory.'/'.$ca_name.'.crt';
  my $ca_cert_der = $ca_directory.'/'.$ca_name.'.der';
  my $ca_crl = $ca_directory.'/'.$ca_name.'_crl.pem';
  my $serial_file = $ca_directory.'/serial';
  my $index_file = $ca_directory.'/index.txt';
  my $openssl_conf_file = $ca_directory.'/confssl.conf';
  my $openssl_conf_ca_file = $ca_directory.'/confssl_ca.conf';
  my $openssl_binary = $cws::conf->{'path'}->{'ssl'};
  my $output_directory = $ca_directory.'/out';

  $openssl_conf->{'dir_ca'} = $ca_directory;
  $openssl_conf->{'ca_name'} = $ca_name;
  $openssl_conf->{'common_name'} = $ca_name;

  unless (-d $ca_directory) {
    $rc = make_path($ca_directory, { mode => 0700 } );
    unless ($rc) {
      $logger->warning('Failed to create directory: `'.$ca_directory.q(').': '.$!);
      goto fail_create_directory;
    }
  }
  else {
    $logger->error('CA already exist: `'.$ca_name.q('));
    return;
  }

  $logger->notice('Creating new authority: `'.$ca_name.q('));

  # 1)

  $rc = open (my $SERIAL, '>', $serial_file);
  unless ($rc) {
    $logger->error('Failed to open for write file: `'.$serial_file.q('));
    goto fail_create_serial;
  }
  $rc = print $SERIAL "01\n";
  unless ($rc) {
    $logger->error('Failed to write file: `'.$serial_file.q('));
    goto fail_create_serial;
  }
  close $SERIAL;

  # 2)

  $rc = open (my $INDEX, '>', $index_file);
  unless ($rc) {
    $logger->error('Failed to open for write file: `'.$index_file.q('));
    goto fail_create_index;
  }

  close $INDEX;

  # 3)

  my $template_file = $cws::conf->{'template'}->{'openssl_conf'};
  $rc = cws::util::apply_template($template_file, $openssl_conf_file, $openssl_conf);
  unless ($rc) {
    $logger->error('Failed to apply template ('.$template_file.') for file: `'.$openssl_conf_file.q(').': '.$!);
    goto fail_creat_ssl_conf;
  }

  my $template_ca_file = $cws::conf->{'template'}->{'openssl_ca_conf'};
  $rc = cws::util::apply_template($template_ca_file, $openssl_conf_ca_file, $openssl_conf);
  unless ($rc) {
    $logger->error('Failed to apply ca template for file: `'.$openssl_conf_ca_file.q(').': '.$!);
    goto fail_creat_ssl_conf;
  }

  # 4)

  my @openssl_create_key_cmd = ($openssl_binary
                               ,'genrsa'
                               ,'-out',$ca_key
                               ,$openssl_conf->{'key_length'});
  $rc = cws::util::system_log($logger, @openssl_create_key_cmd);
  if ($rc) {
    $logger->error('Failed to generate key:'.$ca_key);
    goto fail_create_key;
  }

  # 5)

  if ($with_x509_extensions) {
    my @openssl_create_sign_crt_cmd = ($openssl_binary
                                 ,'req'
                                 ,'-new'
                                 ,'-x509'
                                 ,'-batch'
                                 ,'-days',$openssl_conf->{'validity'}
                                 ,'-config',$openssl_conf_ca_file
                                 ,'-new'
                                 ,'-key',$ca_key
                                 ,'-out',$ca_cert);
    $rc = cws::util::system_log($logger, @openssl_create_sign_crt_cmd);
    if ($rc) {
      $logger->error('Failed to generate csr:'.$ca_cert);
      goto fail_create_csr;
    }
  }
  else {
    my @openssl_create_csr_cmd = ($openssl_binary
                                 ,'req'
                                 ,'-batch'
                                 ,'-config',$openssl_conf_file
                                 ,'-new'
                                 ,'-key',$ca_key
                                 ,'-out',$ca_csr);

    $rc = cws::util::system_log($logger, @openssl_create_csr_cmd);
    if ($rc) {
      $logger->error('Failed to generate csr no ext: '.$ca_csr);
      goto fail_create_csr;
    }

    # 6)

    my @openssl_sign_crt_cmd = ($openssl_binary
                               ,'x509'
                               ,'-req'
                               ,'-days',$openssl_conf->{'validity'}
                               ,'-in',$ca_csr
                               ,'-out',$ca_cert
                               ,'-signkey',$ca_key);
    $rc = cws::util::system_log($logger, @openssl_sign_crt_cmd);
    if ($rc) {
      $logger->error('Failed to sign crt:'.$ca_cert);
      goto fail_create_crt;
    }
  }

  # 7)

  my @openssl_create_der_cmd = ($openssl_binary
                               ,'x509'
                               ,'-outform','der'
                               ,'-in',$ca_cert
                               ,'-out',$ca_cert_der);
  $rc = cws::util::system_log($logger, @openssl_create_der_cmd);
  if ($rc) {
    $logger->error('Failed to create der cert version of crt:'.$ca_cert_der);
    goto fail_create_der;
  }

  # 8)

  $rc = make_path($output_directory, { mode => 0700 } );
  unless ($rc) {
    $logger->error('Failed to create output directory: `'.$output_directory.q('));
    goto fail_create_output_directory;
  }

  # 9)

  $rc = _update_crl($ca_name, $logger);
  unless ($rc) {
    $logger->error('Failed to generate crl:'.$ca_name);
    goto fail_generate_crl;
  }

  # 10)

  $rc = cws::ca::_create_crt($ca_name, 'init', {}, undef, undef, undef, undef, $logger);
  unless ($rc) {
    $logger->error('Failed to generate `init\' crt');
    goto fail_generate_init_crt;
  }

  $rc = _add_admin($ca_name, 'init', $logger);
  unless ($rc) {
    $logger->error('Failed to generate admin file');
    goto fail_generate_admin_file;
  }
  unlink $ca_csr;

  return 1;
fail_generate_admin_file:
fail_generate_init_crt:
fail_generate_crl:
  unlink $ca_crl;
fail_create_output_directory:
  rmdir $output_directory;
fail_create_der:
  unlink $ca_cert_der;
fail_create_crt:
  unlink $ca_cert;
fail_create_csr:
  unlink $ca_csr;
fail_create_key:
  unlink $ca_key;
fail_creat_ssl_conf:
  unlink $openssl_conf_file;
  unlink $openssl_conf_ca_file;
fail_create_serial:
  unlink $index_file;
fail_create_serial:
  unlink $serial_file;
fail_create_directory:
  unlink $ca_logfile;
  rmdir $ca_directory;
  return;
}

# Update the crl for specified CA and copy crl in revocked/ directory
# 1) Generate crl
# 2) Convert crl to der
# 3) Check revocked directory
# 4) Copy crl to revocked directory
sub _update_crl($$;$) {
  (my $ca_name, my $logger, my $force) = @_;
  my $rc = undef;

  my $ca_directory = $cws::conf->{'path'}->{'ca'}.q(/).$ca_name;
  my $revoked_directory = $cws::conf->{'path'}->{'ca'}.q(/).'revoked';

  my $ca_key = $ca_directory.'/'.$ca_name.'.key';
  my $ca_cert = $ca_directory.'/'.$ca_name.'.crt';
  my $ca_crl = $ca_directory.'/'.$ca_name.'_crl.pem';
  my $crl_pem_file = $revoked_directory.'/'.$ca_name.'_crl.pem';
  my $ca_crl_der = $ca_directory.'/'.$ca_name.'_crl.der';
  my $openssl_conf_file = $ca_directory.'/confssl.conf';
  my $openssl_binary = $cws::conf->{'path'}->{'ssl'};

  # 1)

  if ($force) {
    goto generate;
  }
  unless ( -s $ca_crl and -s $ca_crl_der
          and -s $crl_pem_file ) {
    goto generate;
  }


  $rc = open my $new_ca, '>', $ca_directory.'/ca.pem';
  unless ($rc) {
    $logger->error('Failed to open for write file ca.pem');
    return;
  }
  $rc = open my $cafd, '<', $ca_cert;
  unless ($rc) {
    $logger->error('Failed to open for read file ca.pem');
    return;
  }
  $rc = open my $crlfd, '<', $ca_crl;
  unless ($rc) {
    $logger->error('Failed to open for read file ca.pem');
    return;
  }
  while (<$cafd>) {
    print $new_ca $_;
  }
  while (<$crlfd>) {
    print $new_ca $_;
  }
  $rc = close $cafd;
  $rc = close $crlfd;
  $rc = close $new_ca;
  my @cmdverify = ('verify', '-crl_check', '-CAfile', $ca_directory.'/ca.pem', $ca_cert);
  warn join ( ' ', $openssl_binary, @cmdverify );
  $rc = open my $ssl_verif_cmd, '-|', $openssl_binary, @cmdverify;
  unless ($rc) {
    $logger->error('cannot verify ca');
    return;
  }
  while (<$ssl_verif_cmd>) {
    if ( -1 != index $_, "CRL has expired" ) {
      close $ssl_verif_cmd;
      goto generate;
    }
  }
  close $ssl_verif_cmd;
  return 1;

generate:
  my @openssl_crl_cmd = ($openssl_binary
                        ,'ca'
                        ,'-gencrl'
                        ,'-config',$openssl_conf_file
                        ,'-keyfile',$ca_key
                        ,'-cert',$ca_cert
                        ,'-out',$ca_crl);

  $rc = cws::util::system_log($logger, @openssl_crl_cmd);
  if ($rc)
  {
    $logger->error('Failed to generate crl with conf:'.$openssl_conf_file);
    return;
  }

  # 2)

  my @openssl_crl_der_cmd = ($openssl_binary
                            ,'crl'
                            ,'-in',$ca_crl
                            ,'-outform','der'
                            ,'-out',$ca_crl_der);
  $rc = cws::util::system_log($logger, @openssl_crl_der_cmd);
  if ($rc)
  {
    $logger->error('Failed to convert crl to der at '.$ca_crl_der);
    return;
  }

  # 3)

  unless (-d $revoked_directory ) {
    $rc = mkdir $revoked_directory;
    unless ($rc) {
      $logger->error('Failed to create revoked/ directory: '.$revoked_directory.q(:).$!);
      return;
    }
    $rc = chmod 0700, $revoked_directory;
    unless ($rc) {
      $logger->error('Failed to chmod revoked/ directory: '.$revoked_directory.q(:).$!);
      rmdir $revoked_directory;
      return;
    }
  }

  # 4)

  $rc = cp($ca_crl, $revoked_directory.q(/).$ca_name.'_crl.pem.tmp');
  unless ($rc) {
    $logger->error('Failed to copy crl to revoked/ directory: '.$revoked_directory.q(:).$!);
    return;
  }

  $rc = rename ($revoked_directory.q(/).$ca_name.'_crl.pem.tmp', $revoked_directory.q(/).$ca_name.'_crl.pem');
  unless ($rc) {
    $logger->error('Failed to rename tmp crl to revoked/ directory: '.$revoked_directory.q(:).$!);
    return;
  }

  # 5)

  $rc = cp($ca_crl_der, $revoked_directory.q(/).$ca_name.'_crl.der.tmp');
  unless ($rc) {
    $logger->error('Failed to copy crl_der to revoked/ directory: '.$revoked_directory.q(:).$!);
    return;
  }

  $rc = rename ($revoked_directory.q(/).$ca_name.'_crl.der.tmp', $revoked_directory.q(/).$ca_name.'_crl.der');
  unless ($rc) {
    $logger->error('Failed to rename tmp crl_der to revoked/ directory: '.$revoked_directory.q(:).$!);
    return;
  }
  return 1;
}

sub _delete_ca($$)
{
  (my $ca_name, my $logger) = @_;
  my $rc = undef;

  unless (defined $ca_name and $ca_name =~ /^[-_\w]+$/) {
    $logger->error('invalid argument ca_name: `'.$ca_name.q(').q(:));
    return;
  }

  my $ca_directory = $cws::conf->{'path'}->{'ca'}.q(/).$ca_name;
  my $revoked_directory = $cws::conf->{'path'}->{'ca'}.q(/).'revoked';
  my $ca_crl = $revoked_directory.q(/).$ca_name.'_crl.pem';
  my $ca_crl_der = $revoked_directory.q(/).$ca_name.'_crl.der';

  system('/bin/rm', '-Prf', $ca_directory);
  if ($rc) {
    $logger->error('Failed to delete ca directory: `'.$ca_directory.q(').q(:).$!);
    return;
  }

  $rc = unlink($ca_crl);
  unless ($rc) {
    $logger->error('Failed to delete ca crl: `'.$ca_crl.q(').q(:).$!);
    return;
  }

  $rc = unlink($ca_crl_der);
  unless ($rc) {
    $logger->error('Failed to delete ca crl der: `'.$ca_crl_der.q(').q(:).$!);
    return;
  }

  return 1;
}

# Add a certificate name to the admins list
# 1) Create tmp file
# 2) If an admins file exists, we load all content and write it in tmp file
# 3) Write certificate name in tmp file
# 4) Rename tmp file to admins
sub _add_admin($$$) {
  (my $ca_name, my $name, my $logger) = @_;
  my $rc = undef;

  my $ca_directory = $cws::conf->{'path'}->{'ca'}.q(/).$ca_name;
  my $ca_admin_file = $ca_directory.q(/).'admins';

  # 1)
  (my $tmp_fh, my $tmp_file) = tempfile(DIR => $ca_directory);
  unless ($tmp_fh) {
    $logger->error('Failed to create tmp admin file in directory: `'.$ca_directory.q(').q(:).$!);
    goto fail_create_tmp_file;
  }

  # 2)
  if (-s $ca_admin_file) {
    $rc = open my $ca_admin_fh, '<', $ca_admin_file;
    unless ($rc) {
      $logger->error('Failed to open admin file: `'.$ca_admin_file.q(').q(:).$!);
      goto fail_load_old_admin;
    }

    while (my $line = <$ca_admin_fh>) {
      next if ($line =~ /^$name$/);
      $rc = print $tmp_fh $line;
      unless ($rc) {
        $logger->error('Failed to write admin file: '.$!);
        goto fail_write_tmp_file;
      }
    }

    close $ca_admin_fh;
  }

  # 3)

  $rc = print $tmp_fh $name."\n";
  unless ($rc) {
    goto fail_write_tmp_file;
  }
  close $tmp_fh;

  # 4)

  $rc = rename $tmp_file, $ca_admin_file;
  unless ($rc) {
    $logger->error('Failed to rename admin file: `'.$tmp_file.'\'->`'.$ca_admin_file.q(').q(:).$!);
    goto fail_rename_admin_file;
  }

  return 1;
fail_rename_admin_file:
fail_write_tmp_file:
fail_load_old_admin:
  unlink $tmp_file;
fail_create_tmp_file:
  return;
}

# Check if a certificate name is in admin list
sub _is_admin($$$) {
  (my $ca_name, my $name, my $logger) = @_;
  my $rc = undef;

  my $ca_directory = $cws::conf->{'path'}->{'ca'}.q(/).$ca_name;
  my $ca_admin_file = $ca_directory.q(/).'admins';

  unless (-s $ca_admin_file) {
    $logger->error('Missing admin file:`'.$ca_admin_file.q('));
    return;
  }

  $rc = open my $ca_admin_fh, '<', $ca_admin_file;
  unless ($rc) {
    $logger->error('Failed to open admin file: `'.$ca_admin_file.q(').q(:).$!);
    return;
  }

  my $line = <$ca_admin_fh>;
  while ($line) {
    if ($line =~ /^$name$/) {
      close $ca_admin_fh;
      return 1;
    }
    $line = <$ca_admin_fh>;
  }

  close $ca_admin_fh;

  return 0;
}

# Remove a certificate name from admin list
# 1) Check admins file exists
# 2) Open admin file for reading
# 3) Create tmp file
# 4) Copy all name from admin file to tmp file except the name to remove
# 5) Rename tmp file as admin file
sub _remove_admin($$$) {
  (my $ca_name, my $name, my $logger) = @_;
  my $rc = undef;

  my $ca_directory = $cws::conf->{'path'}->{'ca'}.q(/).$ca_name;
  my $ca_admin_file = $ca_directory.q(/).'admins';

  # 1)

  unless (-s $ca_admin_file) {
    $logger->error('Missing admin file:`'.$ca_admin_file.q('));
    return;
  }

  # 2)

  $rc = open my $ca_admin_fh, '<', $ca_admin_file;
  unless ($rc) {
    $logger->error('Failed to open admin file: `'.$ca_admin_file.q(').q(:).$!);
    return;
  }

  # 3)

  (my $tmp_fh, my $tmp_file) = tempfile(DIR => $ca_directory);
  unless ($tmp_fh) {
    $logger->error('Failed to open tmp admin file: `'.$ca_admin_file.q(').q(:).$!);
    goto fail_create_tmp_file;
  }

  # 4)

  while (my $line = <$ca_admin_fh>) {
    if ($line =~ /^$name$/) {
      next;
    }
    $rc = print $tmp_fh $line;
    unless ($rc) {
      $logger->error('Failed to write admin file: '.$!);
      goto fail_write_tmp_file;
    }
  }

  close $ca_admin_fh;
  close $tmp_fh;

  # 5)

  $rc = rename $tmp_file, $ca_admin_file;
  unless ($rc) {
    $logger->error('Failed to rename admin file: `'.$tmp_file.'\'->`'.$ca_admin_file.q(').q(:).$!);
    goto fail_rename_admin_file;
  }

  return 1;
fail_rename_admin_file:
fail_write_tmp_file:
fail_load_old_admin:
  unlink $tmp_file;
fail_create_tmp_file:
  return;
}

sub _is_ca_exists($$) {
  (my $ca_name, my $logger) = @_;

  my $ca_path = $cws::conf->{'path'}->{'ca'};
  unless (-d $ca_path) {
    $logger->error('ca_path missing found: `'.$ca_path.q('));
    return undef;
  }

  my $ca_directory = $ca_path.q(/).$ca_name;

  unless (-d $ca_directory) {
    return 0;
  }

  return 1;
}

sub _get_ca_cert($$$) {
  (my $ca_name, my $format, my $logger) = @_;

  my $rc = undef;

  my $ca_directory = $cws::conf->{'path'}->{'ca'}.q(/).$ca_name;

  my $ca_cert   = $ca_directory.q(/).$ca_name.'.crt';
  my $ca_der    = $ca_directory.q(/).$ca_name.'.der';

  my $output = undef;

  my $send_cert = 0;
  my $send_der = 0;

  unless (defined ($format)) {
    $send_cert = 1;
  }
  elsif ($format eq 'all') {
    $send_cert = 1;
    $send_der = 1;
  }
  elsif ($format eq 'der') {
    $send_der = 1;
  }
  elsif ($format eq 'cert') {
    $send_cert = 1;
  }
  elsif ($format eq 'pem') {
    $send_cert = 1;
  }
  else {
    $logger->error('Invalid format: `'.$format.q('));
    return;
  }

  unless (-d $ca_directory) {
    $logger->error('ca directory not found: `'.$ca_directory.q('));
    return;
  }

  $output = {};

  if ($send_cert and -s $ca_cert) {
    my $cert = cws::util::load_file_as_base64($ca_cert, $logger);
    unless ($cert) {
      $logger->error('Failed to load cert:'.$ca_cert.', not sending');
      $output->{'cert'} = 'error';
    } else {
      $output->{'cert'} = $cert;
    }
  }

  if ($send_der and -s $ca_der) {
    my $der = cws::util::load_file_as_base64($ca_der, $logger);
    unless ($der) {
      $logger->error('Failed to load der:'.$ca_der.', not sending');
      $output->{'der'} = 'error';
    } else {
      $output->{'der'} = $der;
    }
  }

  return $output;
}

sub _get_ca_crl($$$) {
  (my $ca_name, my $format, my $logger) = @_;

  my $rc = undef;

  my $crl_directory = $cws::conf->{'path'}->{'ca'}.'/revoked';
  my $ca_crl   = $crl_directory.q(/).$ca_name.'_crl.pem';
  my $ca_crl_der = $crl_directory.q(/).$ca_name.'_crl.der';

  $rc = cws::root::_update_crl($ca_name, $logger);

  unless (-s $ca_crl) {
    $logger->error('Failed to load der, not sending');
    return;
  }

  my $crl = undef;
  $format = 'pem' unless defined ($format);
  if ($format eq 'pem') {
    $crl = cws::util::load_file_as_base64($ca_crl, $logger);
    unless ($crl) {
      $logger->error('Failed to load crl: `'.$ca_crl.q('));
      return;
    }
  }
  elsif ($format eq 'der') {
    $crl = cws::util::load_file_as_base64($ca_crl_der, $logger);
    unless ($crl) {
      $logger->error('Failed to load crl: `'.$ca_crl_der.q('));
      return;
    }
  } else {
    $logger->error('Invalid format to load crl: `'.$format.q('));
    return;
  }

  return $crl;
}

1;
