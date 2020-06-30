package cws::api::root;
use utf8;
use strict;
use warnings;
use Data::Dumper;
use v5.10;

use cws::root;

use MIME::Base64;

##
# ROOT api
##

sub create($) {
  my $q = shift @_;
  my $rc = undef;

  my $logger = cws::log::new($q);
  my $openssl_conf = $cws::conf->{'ssl'};

  $rc = cws::util::check_required_arguments($q, ['name']);
  unless ($rc) {
    $logger->warning('Missing arguments for create ca');
    return ([400, [], []]);
  }

  my $ca_name = $q->{param}('name');
  my $with_x509_extensions = $q->{param}('with_x509_extensions');

  $openssl_conf = cws::util::override_with_arguments($openssl_conf
                                                    ,$q
                                                    ,['code_country'
                                                     ,'state'
                                                     ,'city'
                                                     ,'organisation'
                                                     ,'organisation_unit'
                                                     ,'email'
                                                     ,'validity'
                                                     ,'cert_valid_time'
                                                     ,'key_length'
                                                     ,'crldays'
                                                     ]);

  $logger->notice('Creating new CA: `'.$ca_name.q('));

  my $ca_directory = $cws::conf->{'path'}->{'ca'}.q(/).$ca_name;

  if (-d $ca_directory) {
    $logger->warning($ca_name.': CA already exists');
    return ([400, [], []]);
  }

  $q->{'ca'} = $ca_name;

  $rc = cws::root::_create_ca($ca_name, $openssl_conf, $logger, $with_x509_extensions);
  unless ($rc) {
    $logger->error('Failed to create CA: `'.$ca_name.q('));
    return ([500, [], []]);
  }

  $rc = cws::ca::_get_and_delete_generated_cert($ca_name, 'init', undef, $logger);
  unless ($rc) {
    $logger->error('Failed to load files to send CA: `'.$ca_name.q('));
    $rc = cws::root::_delete_ca($ca_name, $logger);
    unless ($rc) {
      $logger->alert('Failed to delete CA after an other error, please delete this unusable CA: `'.$ca_name.q('));
    }
    return ([500, [], []]);
  }

  return $q->{header}(-status => 200
                  ,-cert => $rc->{'cert'}
                  ,-pem => $rc->{'pem'}
                  ,-pkcs12 => $rc->{'pkcs12'}
                  ,-key => $rc->{'key'});
}

sub is_ca_exists($) {
  my $q = shift @_;
  my $rc = undef;

  my $logger = cws::log::new($q);

  $rc = cws::util::check_required_arguments($q, ['name']);
  unless ($rc) {
    $logger->warning('is_ca_exists: Missing arguments for testing');
    return ([400, [], []]);
  }

  my $ca_name = $q->{param}('name');

  my $ca_exists = cws::root::_is_ca_exists($ca_name, $logger);
  unless (defined ($ca_exists)) {
    $logger->warning('is_ca_exists: Failed to check if ca exists `'.$ca_name.'\'');
    return ([500, [], []]);
  }

  return $q->{header}(-status => 200, -exists => $ca_exists);
}

sub get_ca_crt($) {
  my $q = shift @_;
  my $rc = undef;

  my $logger = cws::log::new($q);

  $rc = cws::util::check_required_arguments($q, ['name']);
  unless ($rc) {
    $logger->warning('get_ca_crt: Missing arguments to recover');
    return ([400, [], []]);
  }

  my $ca_name = $q->{param}('name');

  my $ca_exists = cws::root::_is_ca_exists($ca_name, $logger);
  unless (defined ($ca_exists)) {
    $logger->warning('get_ca_crt: Failed to check if ca exists `'.$ca_name.'\'');
    return ([500, [], []]);
  }
  unless ($ca_exists) {
    $logger->warning('get_ca_crt: CA `'.$ca_name.'\' does not exists');
    return ([500, [], []]);
  }

  $rc = cws::root::_get_ca_cert($ca_name, $q->{param}('format'), $logger);
  unless ($rc) {
    $logger->error('get_ca_crt: Failed to load CA certificate: `'.$ca_name.q('));
    return ([500, [], []]);
  }
  if ( exists $rc->{'der'} and exists $rc->{'cert'}) {
    return $q->{header}(-status => 200, -der => $rc->{'der'}, -cert => $rc->{'cert'});
  }
  if ( exists $rc->{'cert'}) {
    return $q->{header}(-status => 200, -cert => $rc->{'cert'});
  }
  if ( exists $rc->{'der'}) {
    return $q->{header}(-status => 200, -der => $rc->{'der'});
  }
  return ([500, [], []]);
}

sub get_crl($) {
  my $q = shift @_;
  my $rc = undef;

  my $logger = cws::log::new($q);

  $rc = cws::util::check_required_arguments($q, ['name']);
  unless ($rc) {
    $logger->warning('Missing arguments to recover crl');
    return [ 400, [], [] ];
  }

  my @ca_names = split /,/, $q->{param}('name');
  if ( $#ca_names == 0 )
  {
    my $ca_name = $ca_names[0];
    $rc = cws::root::_get_ca_crl($ca_name, $q->{param}('format'), $logger);
    unless ($rc) {
      $logger->error('Failed to load CA CRL: `'.$ca_name.q('));
      return [ 500, [], [] ];
    }
    return $q->{header}(-status => 200, -crl => $rc);
  }
  if ($q->{param}('mode') eq 'header') {
    my @crlheaders = ( 'Content-Type' , 'text/plain; charset=UTF-8' );
    foreach my $ca_name (@ca_names) {
      push @crlheaders, 'CRL'.$ca_name;
      $rc = cws::root::_get_ca_crl($ca_name, $q->{param}('format'), $logger);
      unless ($rc) {
        $logger->error('Failed to load CA CRL: `'.$ca_name.q('));
        push @crlheaders, 0;
      } else {
        push @crlheaders, $rc;
      }
    }
    return [200, @crlheaders, []];
  }

  return sub {
    my $respond = shift;
    my $writer = $respond->([ 200,
                            ['Content-Type' , 'text/plain; charset=UTF-8']
                            ]);
    foreach my $ca_name (@ca_names) {
      $writer->write('# '.$ca_name."\n");
      $rc = cws::root::_get_ca_crl($ca_name, $q->{param}('format'), $logger);
      unless ($rc) {
        $logger->error('Failed to load CA CRL: `'.$ca_name.q('));
        $writer->write( '404'."\n" );
      } else {
        my $crlfile = decode_base64 $rc;
        $writer->write( $crlfile );
      }
    }
    $writer->close;
  };
}

1;
