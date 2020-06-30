package cws::api::ca;
use utf8;
use strict;
use warnings;
use Data::Dumper;
use v5.10;

use cws::ca;

use MIME::Base64;
##
# CA api
##

#create client
sub new_crt($) {
  my $q = shift @_;
  my $rc = undef;

  my $logger = cws::log::new($q);
  my $ca_name = $q->{'ca'};
  my $openssl_conf = {};

  $rc = cws::util::check_required_arguments($q, ['name']);
  unless ($rc) {
    $logger->warning('Missing arguments for new_crt');
    return ([400, [], []]);
  }

  my $name = $q->{param}('name');

  unless ($name =~ /\A[-\w\.]+\Z/) {
    $logger->warning('name for new_crt does not match regex: `'.$name.q('));
    return ([400, [], []]);
  }

  $rc = cws::ca::_is_cert_exists($ca_name, $name, $logger);
  unless (defined ($rc)) {
    $logger->error($ca_name.': Failed to chech if crt exists');
    return ([500, [], []]);
  }
  if ($rc) {
    $logger->warning($ca_name.': certificate with name `'.$name.'\' already exists');
    return ([400, [], []]);
  }
  

  $openssl_conf = cws::util::override_with_arguments($openssl_conf
                                                     ,$q
                                                     ,['code_country'
                                                       ,'state'
                                                       ,'city'
                                                       ,'organisation'
                                                       ,'organisation_unit'
                                                       ,'email'
                                                       ,'cert_valid_time'
                                                       ,'key_length'
                                                       ]);

  $rc = cws::ca::_create_crt_without_csr($ca_name, $name, $openssl_conf, $q->{param}('extensions'), $q->{param}('passwd'), $logger);
  unless ($rc) {
    $logger->error('Failed to create cert');
    return ([500, [], []]);
  }

  my $admin = $q->{param}('admin');
  if (defined ($admin) and $admin == 1) {
    $rc = cws::root::_add_admin($ca_name, $name, $logger);
    unless ($rc) {
      $rc = cws::ca::_revoke_certificate($ca_name, $name, $logger);
      unless ($rc) {
        $logger->alert('ERROR WHILE REVOKING NEW CERTIFICATE `'.$name.'\' FROM CA: `'.$ca_name.'\' AFTER ERROR IN add_admin');
      }
      return ([500, [], []]);
    }
  }

  $rc = cws::ca::_get_and_delete_generated_cert($ca_name, $name, $q->{param}('format'), $logger);
  unless ($rc) {
    $logger->error('Failed to send new certificate');
    $rc = cws::ca::_revoke_certificate($ca_name, $name, $logger);
    unless ($rc) {
      $logger->alert('ERROR WHILE REVOKING NEW CERTIFICATE `'.$name.'\' FROM CA: `'.$ca_name.'\' AFTER ERROR IN _get_and_delete_generated_cert');
    }
    return ([500, [], []]);
  }

  my $mode = $q->{param}('mode');
  if ( $mode and $mode eq 'body' ) {
    my $format = $q->{param}('format');
    if ( $format eq 'pem' ) {
      my $pfile = decode_base64 $rc->{'pem'};
      return ([200, [ 'Content-Type' => 'application/x-pem-file' ], [ $pfile ]] );
    }
    if ( $format eq 'pkcs12' ) {
      my $pfile = decode_base64 $rc->{'pkcs12'};
      return ([200, [ 'Content-Type' => 'application/x-pkcs12' ], [ $pfile ]] );
    }
  }

  return $q->{header}(-status => 200
                  ,-cert => $rc->{'cert'}
                  ,-pem => $rc->{'pem'}
                  ,-pkcs12 => $rc->{'pkcs12'}
                  ,-key => $rc->{'key'});
}

sub new_crt_with_csr($) {
  my $q = shift @_;
  my $rc = undef;

  my $logger = cws::log::new($q);

  $rc = cws::util::check_required_arguments($q, ['csr','csr_format']);
  unless ($rc) {
    $logger->warning('Missing arguments for new_crt');
    return ([400, [], []]);
  }

  my $ca_name = $q->{'ca'};
  my $openssl_conf = {};

  my $csr = $q->{param}('csr');
  unless ($csr) {
    $logger->warning('Missing csr for new_crt_with_csr');
    return ([400, [], []]);
  }

  my $csr_format = $q->{param}('csr_format');
  unless ($csr_format eq 'pem' or $csr_format eq 'der') {
    $logger->warning('Invalid csr_format, should be `pem` or `der` but was `'.$csr_format.'\'');
    return ([400, [], []]);
  }

  $openssl_conf = cws::util::override_with_arguments($openssl_conf
                                                     ,$q
                                                     ,['code_country'
                                                       ,'state'
                                                       ,'city'
                                                       ,'organisation'
                                                       ,'organisation_unit'
                                                       ,'email'
                                                       ,'cert_valid_time'
                                                       ,'key_length'
                                                       ]);

  $rc = cws::ca::_create_crt_with_csr($ca_name, $openssl_conf, $q->{param}('extensions'), $csr, $csr_format, $q->{param}('passwd'), $logger);
  unless ($rc) {
    $logger->error('Failed to create new certificate with given csr');
    return ([500, [], []]);
  }

  my $name = $rc;

  $rc = cws::ca::_get_and_delete_generated_cert($ca_name, $name, $q->{param}('format'), $logger);
  unless ($rc) {
    $logger->error('Failed to send new certificate');
    $rc = cws::ca::_revoke_certificate($ca_name, $name, $logger);
    unless ($rc) {
      $logger->alert('ERROR WHILE REVOKING NEW CERTIFICATE `'.$name.'\' FROM CA: `'.$ca_name.'\' AFTER ERROR IN _get_and_delete_generated_cert');
    }
    return ([500, [], []]);
  }
  
  return $q->{header}(-status => 200
                  ,-cert => $rc->{'cert'}
                  ,-pem => $rc->{'pem'}
                  ,-pkcs12 => $rc->{'pkcs12'});
}

sub auth($) {
  my $q = shift @_;
  my $rc = undef;

  my $logger = cws::log::new($q);
  my $ca_name = $q->{'ca'};
  my $cn = $q->{'cn'};

  $rc = cws::root::_is_admin($ca_name, $cn, $logger);
  unless (defined ($rc)) {
    $logger->error('Failed to check if cn is admin');
    return ([500, [], []]);
  }

  return ([200, [ 'Content-Type' => 'application/json' ], ['{"admin":'.$rc.'}']]);
}

sub client_list($) {
  #TODO: should getting list of cn be restricted to admin ?
  my $r =  shift @_;
  #FIXME
  return ([500, [], []]);
}

sub is_cert($) {
  my $q = shift @_;
  my $rc = undef;
print "cert\n";
  my $logger = cws::log::new($q);
  my $ca_name = $q->{'ca'};
  my $mode = $q->{param}('mode');
  my $name = $q->{param}('name');

  my @names = split ',', $name; #TODO

  my $is = cws::ca::_is_cert_exists($ca_name, $names[0], $logger);
  if (not defined $is) {
    return ([500, [], []]);
  }

  if (defined $mode and $mode eq 'shell') {
    if ($is) {
      return ([200, [], []]);
    } else {
      return ([404, [], []]);
    }
  }
  if (defined $mode and $mode eq 'body') {
    if ($is) {
      return ([200, [ 'Content-Type' => 'application/json' ], ["true"]]);
    } else {
      return ([200, [ 'Content-Type' => 'application/json' ], ["false"]]);
    }
  }

  if ($is) {
    return ([200, [ 'Exists' => 1], []]);
  }
  return ([200, [ 'Exists' => 0], []]);
}

sub revoke($) {
  my $q = shift @_;
  my $rc = undef;

  my $logger = cws::log::new($q);
  my $ca_name = $q->{'ca'};
  my $openssl_conf = {};

  $rc = cws::util::check_required_arguments($q, ['name']);
  unless ($rc) {
    $logger->warning('Missing arguments for new_crt');
    return ([400, [], []]);
  }

  my $name = $q->{param}('name');

  $logger->notice('Revoking certificate: `'.$name.q('));


  my @names = split ',', $name;
  for my $n (@names) {

    $rc = cws::ca::_is_cert_exists($ca_name, $n, $logger);
    unless (defined ($rc)) {
      $logger->error('Failed to check if certificate exists `'.$n.q('));
      return ([500, [], []]);
    }
    unless ($rc) {
      $logger->info('Certificate does not exists or was already revoked: `'.$n.q('));
      next;
    }

    $rc = cws::ca::_revoke_certificate($ca_name, $n, $logger);
    unless ($rc) {
      $logger->error('Failed to revoke certificate `'.$n.q('));
      return ([500, [], []]);
    }
  }

  return $q->{header}(-status => 200);
}

sub close($) {
  my $q = shift @_;
  my $rc = undef;

  my $logger = cws::log::new($q);
  my $ca_name = $q->{'ca'};

  $rc = cws::root::_delete_ca($ca_name, $logger);
  unless ($rc) {
    $logger->error('Failed to DELETE CA: `'.$ca_name.q('));
    return ([500, [], []]);
  }

  return $q->{header}(-status => 200);
}
1;
