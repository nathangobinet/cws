#!/usr/bin/env perl
use strict;
use utf8;
use warnings;
use v5.10;
use Data::Dumper;
use MIME::Base64;

use Mojolicious::Lite -signatures;

use POSIX qw(setuid setgid);
use Sys::Syslog qw(:standard :macros);
use File::Path qw(make_path remove_tree);

use cws;
use cws::util;
use cws::api::root;
use cws::api::ca;

# Init
openlog('cws', 'perror,nofatal,pid', LOG_DAEMON);
setup_SIG();
cws::init();
clean_tmp_dir();

sub setup_SIG {
  $SIG{TERM} = $SIG{INT} = $SIG{QUIT} = sub {
    unlink $cws::conf->{path}->{fcgi};
    closelog();
    die;
  };

  $SIG{HUP} = sub {
    info('alive');
  };
}

sub clean_tmp_dir {
  # Clean tmp dir
  if (-d $cws::conf->{path}->{out}) {
    remove_tree($cws::conf->{path}->{out});
  }
  my $rc = mkdir $cws::conf->{path}->{out};
  unless ($rc) {
    die sprintf('Failed to create tmp directory "%s" : %s -', $cws::conf->{path}->{out}, $!);
  }
}

# Routes

under sub {
  my $c = shift;

  # Utility to render [[status], [], []]
  $c->{'render_response'} = sub {
    my @response = shift;
    $c->rendered($response[0][0]);
  };

  # Wrapper containing controller info for cws functions
  $c->{'cws_wrapper'} = {};
  # Add wrapper for GET param
  $c->{'cws_wrapper'}{'param'} = sub {
    return $c->param(@_);
  };

};

group {
  under '/ca' => sub {
    my $c = shift;
    # Add wrapper to set header
    $c->{'cws_wrapper'}{'header'} = sub {
      my %args = @_;
      while (my($key, $value) = each %args) {
        $c->res->headers->add($key => $value);
      }
      return ([$args{'-status'}, [], []]);
    };
  };

  get '/create' => sub ($c) {
    my $rc = cws::api::root::create($c->{'cws_wrapper'});
    $c->{'render_response'}($rc);
  };

  get '/close' => sub ($c) {
    # close espect {'ca'} to get name
    $c->{'cws_wrapper'}{'ca'} = $c->param('name');
    my $rc = cws::api::ca::close($c->{'cws_wrapper'});
    $c->{'render_response'}($rc);
  };
};

app->start;
