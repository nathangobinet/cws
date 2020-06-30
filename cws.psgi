#!/usr/bin/env perl
use strict;
use utf8;
use warnings;
use v5.10;
use Data::Dumper;

use POSIX qw(setuid setgid);
use Sys::Syslog qw(:standard :macros);
use File::Path qw(make_path remove_tree);
use Plack::Runner;
use Plack::Builder;
use Plack::Request;

use cws;
use cws::util;
use cws::api::root;
use cws::api::ca;

use MIME::Base64;

my $client_id = 0;
openlog('cws', 'perror,nofatal,pid', LOG_DAEMON);

$SIG{TERM} = $SIG{INT} = $SIG{QUIT} = sub {
	unlink $cws::conf->{path}->{fcgi};
	closelog();
	die;
};


$SIG{HUP} = sub {
	info('alive');
};


cws::init();

# Clean tmp dir
if (-d $cws::conf->{path}->{out}) {
	remove_tree($cws::conf->{path}->{out});
}
my $rc = mkdir $cws::conf->{path}->{out};
unless ($rc) {
	die 'Failed to create tmp directory: `'.$cws::conf->{path}->{out}.'\'';
}

my $runner = Plack::Runner->new;
# -s FCGI -l /var/run/cws.fcgi
$runner->parse_options(@ARGV);

my $base_app = sub {
  my $q = shift @_;
  my $data;
  $data = [ Dumper $q ];
  return [ 200, [ "Content-Type" => "text/plain" ], $data ];
};

my $builder = builder {
	enable sub {
		my $current_app = shift @_;
		sub {
			my $env = shift @_;
			my $rc = undef;
			$client_id++;
			# do preprocessing
			my $logger = cws::log::new($env);
			my $q = Plack::Request->new($env);

			# # placksremove script name from path_info to bind submodule
			# # put it back to directly answer with the right script
			# FIXME: http://search.cpan.org/dist/Plack-0.9979/lib/Plack/Handler/FCGI.pm#nginx
			if (length $env->{SCRIPT_NAME} > 0) {
				$env->{PATH_INFO} = $env->{SCRIPT_NAME};
			}

			# Only accept connection locally or behind a nicely configure nginx
			if ($ENV{CITYDEBUG}) {
				$env->{HTTPS} = 'on'; #does not check for security on local
				if ($env->{REQUEST_URI} =~ m#^/ca/# ) {
					# normally nginx will authenticate the client certifcate
					# and push :
					#    fastcgi_param HTTPS                on;
					#    fastcgi_param SCRIPT_FILENAME      $fastcgi_script_name;
					#    # http://nginx.org/en/docs/http/ngx_http_ssl_module.html
					#    fastcgi_param CLIENTS              $ssl_client_verify;
					#    fastcgi_param AUTH                 $ssl_client_s_dn;
					#    fastcgi_param CA                   $ssl_client_i_dn;
					#    fastcgi_param CLIENT_CERT          $ssl_client_cert;
					# curl -H or http header are HTTP_ prefixed
					my @x = split ':', $q->param('certificate');
					$env->{CLIENTS} = 1;
					$env->{AUTH} = decode_base64($x[0]);
					$env->{CA} = decode_base64($x[1]);
					$env->{CLIENT_CERT} = decode_base64($x[2]);
				} else {
					$env->{AUTH} = 'root';
				}
			}

			unless (defined $env->{HTTPS} and $env->{HTTPS} eq 'on') {
				$logger->warning('non https connection on: `'
					.$env->{SCRIPT_FILENAME}.q('));
				return [ 403, [], [] ];
			}
			unless (defined $env->{AUTH} and length $env->{AUTH} > 0) {
				$logger->warning('non valid https connection on: `'
					.$env->{REQUEST_URI}.q('));
				return [ 403, [], [] ];
			}

			# sanitize
			my $name = $q->param('name');
			if (defined $name and -1 != index $name, '/') {
				$logger->err('invalid name parameter: `'.$name.q('));
				return [ 400, [], [] ];
			}

			unless ( $env->{AUTH} eq 'root') {
				# check authentication
				(my $ca_name, my $cert_name) =
				cws::util::_get_issuer_ca_from_certificate( $env->{CLIENT_CERT}
					, $env->{CA}
					, $env->{AUTH}
					, $logger);

				unless (defined $ca_name and length $ca_name > 0)  {
					$logger->err('bad auth for `'.$env->{CA}.'\'');
					return [ 403, [], [] ];
				}

				$env->{ADMIN} = cws::root::_is_admin($ca_name, $cert_name, cws::log::new($q));
				$env->{ca} = $ca_name;
				$env->{cn} = $cert_name;
			}

			# glue to FCGI base api and code to  handle mode=shell/body/header
			$env->{'logger'} = $logger;
			$env->{'request'} = $q;
			$env->{'param'} = sub {
				$q->param(@_);
			};
			$env->{'header'} = sub {
				my (%h) = @_;
				my $code = 200;
				my $content = [];
				my %nh;
				foreach my $k (keys %h) {
					if ($k eq '-status') {
						$code = $h{$k};
						next;
					}
					if ($k eq '-content') {
						$content = $h{$k};
						next;
					}
					if ($k eq '-type') {
						$nh{'Content-Type'} = $h{$k};
					} else {
						$nh{substr $k,1} = $h{$k};
					}
				}

				my $mode = $env->{'param'}('mode');
				if (defined $mode and $mode eq 'shell' and $code == 200 ) {
					$code = 404 if (defined $h{'-exists'} and $h{'-exists'} ne '1');
				}
				elsif ($code == 200 and exists $h{'-exists'}
					and scalar @$content == 0
					and defined $mode and $mode eq 'body') {
					$nh{'Content-Type'} = 'application/json';
					$content = [ $h{'-exists'} == 1 ? 'true' : 'false' ];
				}
				elsif ($code == 200 and exists $h{'-crl'}
					and defined $mode and $mode =~ '^(body|shell)$' ) {
					$nh{'Content-Type'} = 'application/x-pkcs7-crl';
					$content = [ decode_base64( $h{'-crl'} ) ];
				}
				elsif ($code == 200 and exists $h{'-cert'}
					and defined $mode and $mode =~ '^(body|shell)$' ) {
					$nh{'Content-Type'} = 'application/x-x509-ca-cert';
					$nh{'Content-Type'} = 'application/x-pem-file' if (exists $h{'-key'});
					$content = [ decode_base64( $h{'-cert'} ) ];
					$content = [ $content->[0]."\r\n".decode_base64( $h{'-key'} ) ] if (exists $h{'-key'});
				}

				$q->header(%nh) if (scalar keys %nh > 0);
				# FIXME
				# https://www.mail-archive.com/opensuse-commit@opensuse.org/msg105479.html
				# psgi_flatten / flatten
				if ( $q->headers->can('flatten') ) {
					return [$code, $q->headers->flatten, $content];
				} else {
					return [$code, $q->headers->psgi_flatten, $content];
				}
			};

			# Lock and process
			$rc = cws::ca_lock($env);
			unless ($rc) {
				$logger->err('Failed to acquire lock for ca `'.$q->{'ca'}.'\' #'.$client_id);
				return [ 500, [], [] ];
			};

			my $res;
			eval {
				$res = $current_app->($env);
			};
			if ($@) {
				$logger->err('Eval error for #'.$client_id.': '.$@);
				return [ 500, [], [] ];
			}
			cws::ca_unlock($env);
			return $res;
		};
	};

	mount '/configuration' => sub {
		my $q = shift @_;
		unless ($q->{REMOTE_ADDR} eq '127.0.0.1') {
			return [ 403, [], [] ];
		}
		return [ 200
			, [ "Content-Type" => "text/plain" ]
			, [ Dumper $cws::conf ]
			];
	};
 	if ($ENV{CITYDEBUG}) {
		mount '/debug' => $base_app;
	}
	mount '/shutdown' => sub {
		my $q = shift @_;
		unless ($q->{REMOTE_ADDR} eq '127.0.0.1') {
			return [ 403, [], [] ];
		}
		exit 1;
	};
	mount '/test' => sub {
		return [ (-d $cws::conf->{path}->{out}) ? 200 : 500
			, []
			, []
			];
	};

	# actions root
	mount '/create.pl' => sub {
		my $q = shift @_;
		return [ 403, [], [] ] unless ($q->{AUTH} eq 'root');
		cws::api::root::create($q);
	};
	mount '/get_crl.pl' => sub {
		my $q = shift @_;
		return [ 403, [], [] ] unless ($q->{AUTH} eq 'root');
		cws::api::root::get_crl($q);
	};
	mount '/get_ca_crt.pl' => sub {
		my $q = shift @_;
		return [ 403, [], [] ] unless ($q->{AUTH} eq 'root');
		cws::api::root::get_ca_crt($q);
	};
	mount '/is_ca_exists.pl' => sub {
		my $q = shift @_;
		return [ 403, [], [] ] unless ($q->{AUTH} eq 'root');
		cws::api::root::is_ca_exists($q);
	};

	# actions ca
	mount '/ca/auth.pl' => sub {
		my $q = shift @_;
		return [ 403, [], [] ] unless (exists $q->{ADMIN});
		cws::api::ca::auth($q);
	};

	# actions admin ca
	mount '/ca/new_crt.pl' => sub {
		my $q = shift @_;
		return [ 403, [], [] ] unless ($q->{ADMIN});
		cws::api::ca::new_crt($q);
	};
	mount '/ca/new_crt_with_csr.pl' => sub {
		my $q = shift @_;
		return [ 403, [], [] ] unless ($q->{ADMIN});
		cws::api::ca::new_crt_with_csr($q);
	};
	mount '/ca/is_cert.pl' => sub {
		my $q = shift @_;
		return [ 403, [], [] ] unless ($q->{ADMIN});
		cws::api::ca::is_cert($q);
	};
	mount '/ca/revoke.pl' => sub {
		my $q = shift @_;
		return [ 403, [], [] ] unless ($q->{ADMIN});
		cws::api::ca::revoke($q);
	};
	mount '/ca/close.pl' => sub {
		my $q = shift @_;
		return [ 403, [], [] ] unless ($q->{ADMIN});
		cws::api::ca::close($q);
	};
};

$runner->run($builder);
