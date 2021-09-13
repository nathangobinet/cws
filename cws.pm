package cws;

use strict;
use warnings;
use Data::Dumper;
use Sys::Syslog qw(:standard :macros);
use v5.10;
use Fcntl qw(:flock);
use List::Util qw(first);
##
# Configuration
##

our $conf;

sub readconf($) {
  my $section = undef;
  my @errors = ();
  open my $f, '<', $_[0] or do {
    return ('cannot open:'.$_[0].':'.$!);
  };

  my $line_number = 0;
  while (<$f>) {
    my $line = $_;
    chomp $line;
    $line_number++;

    # Ignore empty line
    next if ($line =~ /\A\s*\Z/);
    # Ignore comment.
    next if ($line =~ /\A\s*;/);
    
    # Matching [section]
    if ($line =~ /\A\[(?<section_name>.+)\]\Z/) {
      $section = $+{'section_name'};
      next;
    # Matchin key=value
    } elsif ($line =~ /\A(?<key>[\-\w\.]+)=(?<value>.*)\Z/)  {
      if (defined $section) {
        $conf->{ $section }->{ $+{'key'} } = $+{'value'};
      } else {
        push @errors,$_[0] . ':' . $line_number . ': missing [section] declaration before key=value line';
      }
    } else {
      push @errors, $_[0] . ':' . $line_number . ': bad format';
    }
  }
  close $f;
  return @errors;
}

sub init {
  my $confpath = get_conf_path();
  my @e = readconf($confpath);
  if ( $#e ne -1 ) {
    my $err = join "\n", @e;
    die 'configuration problem:'."\n".$err;
  }
}

sub get_conf_path {
  my $environment = $ENV{ENVIRONMENT};
  # If environment is not defined, set up default as production
  if (not defined $environment) {
    $environment = 'PRODUCTION';
  }

  my $prefix = $environment eq 'PRODUCTION' ? 'prod' : 'dev';
  my $confpath = '/etc/cws/global.'.$prefix.'.conf';

  # Fallback to default conf
  if (not -e $confpath) {
    $confpath = '/etc/cws/global.conf';
  }

  return $confpath;
}

##
# outside interraction
##
sub reload_nginx() {
  system('nginx -s reload');
}


###
# MT: cant do multiple action on one ca
###
sub ca_lock($) {
  my $q = shift @_;

  my $p = $cws::conf->{path}->{out};
  if ( not defined $q->{ca} or length $q->{ca} < 1 ) {
    $p = $p.'/'.'.lock';
  } else {
    $p = $p.'/'.$q->{ca}.'.lock';
  }
  open(my $ca_lock_fd, '>>',  $p) or do {
    return undef;
  };
  $q->{ 'ca_lock' } = $ca_lock_fd;

  return flock($ca_lock_fd, LOCK_EX);
}

sub ca_unlock($) {
  my $q = shift @_;
  flock($q->{'ca_lock'}, LOCK_UN);
  close($q->{'ca_lock'});
}

###############################################################################
# right and auths                                                             #
###############################################################################
sub add_allowed_client($) {
  my $args = $_[0];
  my $new_client = $args->{param}('new_crt');
  make_path( $args->{ dir_ca }.'/allowed_clients', { mode => 0700 } );
  #error is check with the file creation
  my $fname = $args->{ dir_ca }.'/allowed_clients/'.$new_client;
  open (my $admin, '>', $fname) or do {
    error($args,'cannot write file `'.$fname.'\'');
    return 0;
  };
  print $admin $args->{ cn };
  close $admin;
  return 1;
}

sub check_client_allowed($) {
  my $args = $_[0];
  my $fname = $args->{ dir_ca }.'/allowed_clients/'.$args->{ cn };
  if ( -f $fname ) {
    debug($args, 'found allowed_client:`'.$args->{ cn }.'\'');
    return 1;
  } else {
    info($args,'client not authorized:`'.$args->{ cn }.'\'');
  }
  return 0;
}

package cws::log;
use Data::Dumper;
use Carp qw(longmess);
use Sys::Syslog qw(:standard :macros);
##
# loggin
##

sub open_logfile()
{
  my $self = shift @_;
  if (not exists $self->{'logger_fh'} and exists $self->{'q'}->{'ca'}) {
    my $ca_name = $self->{'q'}->{'ca'};
    my $ca_directory = $cws::conf->{'path'}->{'ca'}.q(/).$ca_name;
    my $ca_logfile = $ca_directory.q(/).'log';

    if (-d $ca_directory) {
      my $rc = open my $fh, '>>', $ca_logfile;
      unless ($rc) {
        syslog('err', 'Failed to open file to log ca info: `'.$ca_logfile.q(').q(:).$!);
      }
      else {
        $self->{'logger_fh'} = $fh;
      }
    }
  }
}
sub do_log($$) {
  my $self = shift @_;
  (my $level, my $msg) = @_;
  
  syslog($level, $msg);

  $self->open_logfile();

  if (exists $self->{'logger_fh'} and defined($self->{'logger_fh'})) {
    my $fh = $self->{'logger_fh'};
    print $fh $msg."\n";
  }
}

sub intro_log($) {
  my $r = shift @_;
  my $msg = '';
  $msg .= '['.$r->{'package'}.']' if (exists $r->{'package'});
  $msg .= '['.$r->{'function_name'}.']' if (exists $r->{'function_name'});
  $msg .= '['.$r->{'uid'}.']' if (exists $r->{'uid'});
  $msg .= '['.$r->{'REMOTE_ADDR'}.':'.$r->{'REMOTE_PORT'}.']' if (exists $r->{'REMOTE_ADDR'});
  return $msg;
}

sub alert($$) {
  my $self = shift @_;
  my $msg = '[ALR]'.intro_log($self->{'q'}).$_[0];
  $self->do_log('alert',$msg);
}

sub error($$) {
  my $self = shift @_;
  my $msg = '[ERR]'.intro_log($self->{'q'}).$_[0];
  $self->do_log('err',$msg);
}

sub err($$) {
  my $self = shift @_;
  return $self->error($_[0]);
}

sub warning($$) {
  my $self = shift @_;
  my $msg = '[WRN]'.intro_log($self->{'q'}).$_[0];
  $self->do_log('warning',$msg);
}

sub notice($$) {
  my $self = shift @_;
  my $msg = '[NOT]'.intro_log($self->{'q'}).$_[0];
  $self->do_log('notice',$msg);
}

sub info($$) {
  my $self = shift @_;
  my $msg = '[INF]'.intro_log($self->{'q'}).$_[0];
  $self->do_log('info',$msg);
}

sub debug($$) {
  my $self = shift @_;
  my $msg = '[DBG]'.intro_log($self->{'q'}).$_[0];
  $self->do_log('debug',$msg);
}
sub new($) {
  (my $r) = @_;
  return bless {'q'=>$r}, 'cws::log';
}
sub DESTROY {
  my $self = shift;

  if (exists $self->{'logger_fh'} and defined($self->{'logger_fh'})) {
    close $self->{'logger_fh'};
    delete $self->{'logger_fh'};
  }
}
1;
