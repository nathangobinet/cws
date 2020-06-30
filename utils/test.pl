#! /bin/perl
use strict;
use warnings;
use v5.10;
use utf8;
use Data::Dumper;
use File::Copy;
use File::Path qw(make_path);
use Cwd;
use MIME::Base64;

if (system('which', 'curl')) {
	say 'no curl';
	exit 1;
}

sub lf {
  open my $F, '<', $_[0];
  local $/ = undef;
  return <$F>;
}

my $certificates_path = './test/ssl';
make_path($certificates_path);
make_path('./test/ca');
make_path('./test/tmp');
system('cp', '-r', '../template', './test/') and die "Copy failed: $!";
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

open my $f, '>', './test/global.conf';
my $p = cwd().'/test';
print $f "[ssl]
code_country=FR
state=France
city=Paris
organisation=Citypassenger
organisation_unit=MobileIT
common_name=CityCloudClient0000
email=support\@citypassenger.com
key_length=2048
;client certificate validity
validity=3650
;crl validity
crldays=10
;ca validity
cert_valid_time=3650
;where to store the file
[path]
out=$p/tmp
ca=$p/ca/
ssl=/usr/bin/openssl
extensions_file=$p/../../conf/radius-xp.ext
fcgi=/var/run/cws.fcgi
[template]
openssl_conf=$p/../../template/openssl.conf
openssl_ca_conf=$p/../../template/openssl_ca.conf
";
close $f;

my $pid_psgi = fork;
unless (defined($pid_psgi)) {
syslog('err','Failed to fork:'.$!);
	exit 1;
}
unless ($pid_psgi) {
	$ENV{CITYDEBUG} = 1;
	exec('perl', '-w', '-I', '../'
		  , '../cws.psgi'
		  , '-c', './test/global.conf'
		  , '--port', '9090'
		  , '--host', '127.0.0.1' );
}

sleep 1;
my $try = 60;

while ($try) {
	$try--;
	if (system('nc', '-zv', '127.0.0.1', 9090)) {
		sleep 1;
	} else {
		last;
	}
}

sub getheader {
  my $h = shift @_;
  my $v = shift @_;
  my @r = ();
  open my $Ff, '-|', @_ or die Dumper(@_)." oops ".$!;
  while (<$Ff>) {
    my $i = 0;
    my $line = $_;
    foreach my $head (@$h) {
      my $val = $v->[$i++];
      if ($line =~ /^$head:\s(.*)\r$/i) {
        push @r, ":".$1 eq ":".$val ? "OK" : "Failed:".$head;
      }
    }
  }
  close $Ff;
  return \@r;
}

my $hr;
my @x;
say 'TEST';
say '---------------------------------------------------------------------------';
system('curl', 'http://127.0.0.1:9090/test');
say '===========================================================================';
say 'CREATE';
say '---------------------------------------------------------------------------';
system('curl', 'http://127.0.0.1:9090/create.pl?name=coreca&state=CA&cert_valid_time=2');
goto myclose unless ( -d './test/ca/coreca' );
$hr = system(' openssl verify  -crl_check -CRLfile ./test/ca/coreca/coreca_crl.pem'
            .' -CAfile ./test/ca/coreca/coreca.crt'
            .' ./test/ca/coreca/01.pem');
goto myclose unless ( $hr == 0 );
say '===========================================================================';
say 'is_ca_exists';
say '---------------------------------------------------------------------------';
$hr = getheader ( ['Exists'], ['0']
          , 'curl', '-D-', 'http://127.0.0.1:9090/is_ca_exists.pl?name=foobar');
say Dumper($hr);
@x = grep /OK/, @$hr;
goto myclose unless ( scalar @x eq @$hr and scalar @x > 0);
$hr = system(' openssl verify  -crl_check -CRLfile ./test/ca/coreca/coreca_crl.pem'
            .' -CAfile ./test/ca/coreca/coreca.crt'
            .' ./test/ca/coreca/01.pem');
goto myclose unless ( $hr == 0 );
say '---------------------------------------------------------------------------';
$hr = getheader ( ['Exists'], ['1']
          , 'curl', '-D-', 'http://127.0.0.1:9090/is_ca_exists.pl?name=coreca');
say Dumper($hr);
@x = grep /OK/, @$hr;
goto myclose unless ( scalar @x eq @$hr and scalar @x > 0 );
$hr = system(' openssl verify  -crl_check -CRLfile ./test/ca/coreca/coreca_crl.pem'
            .' -CAfile ./test/ca/coreca/coreca.crt'
            .' ./test/ca/coreca/01.pem');
goto myclose unless ( $hr == 0 );
say '---------------------------------------------------------------------------';
say 'is ca exist SHELL';
$hr = system('curl', '--fail', '-v', 'http://127.0.0.1:9090/is_ca_exists.pl?name=coreca&mode=shell');
goto myclose unless ($hr == 0);
$hr = system('curl', '--fail', '-v', 'http://127.0.0.1:9090/is_ca_exists.pl?name=fgfgcoreca&mode=shell');
goto myclose unless ($hr != 0);
say '---------------------------------------------------------------------------';
$hr = system(' openssl verify  -crl_check -CRLfile ./test/ca/coreca/coreca_crl.pem'
            .' -CAfile ./test/ca/coreca/coreca.crt'
            .' ./test/ca/coreca/01.pem');
goto myclose unless ( $hr == 0 );
$hr = getheader ( ['Exists'], ['1']
          , 'curl', '-D-', 'http://127.0.0.1:9090/is_ca_exists.pl?name=coreca&mode=header');
say Dumper($hr);
@x = grep /OK/, @$hr;
goto myclose unless ( scalar @x eq @$hr and scalar @x > 0 );
$hr = system(' openssl verify  -crl_check -CRLfile ./test/ca/coreca/coreca_crl.pem'
            .' -CAfile ./test/ca/coreca/coreca.crt'
            .' ./test/ca/coreca/01.pem');
goto myclose unless ( $hr == 0 );
say '---------------------------------------------------------------------------';
$hr = `curl -v 'http://127.0.0.1:9090/is_ca_exists.pl?name=coreca&mode=body'`;
goto myclose unless ($hr eq 'true');
$hr = system(' openssl verify  -crl_check -CRLfile ./test/ca/coreca/coreca_crl.pem'
            .' -CAfile ./test/ca/coreca/coreca.crt'
            .' ./test/ca/coreca/01.pem');
goto myclose unless ( $hr == 0 );
say '---------------------------------------------------------------------------';
$hr = `curl -v 'http://127.0.0.1:9090/is_ca_exists.pl?name=dqwdqdwq&mode=body'`;
goto myclose unless ($hr eq 'false');
$hr = system(' openssl verify  -crl_check -CRLfile ./test/ca/coreca/coreca_crl.pem'
            .' -CAfile ./test/ca/coreca/coreca.crt'
            .' ./test/ca/coreca/01.pem');
goto myclose unless ( $hr == 0 );
say '===========================================================================';
say 'get_ca_crt';
say '---------------------------------------------------------------------------';
system('curl', 'http://127.0.0.1:9090/get_ca_crt.pl?name=foobar');
$hr = system(' openssl verify  -crl_check -CRLfile ./test/ca/coreca/coreca_crl.pem'
            .' -CAfile ./test/ca/coreca/coreca.crt'
            .' ./test/ca/coreca/01.pem');
goto myclose unless ( $hr == 0 );
say '---------------------------------------------------------------------------';
system('curl', 'http://127.0.0.1:9090/get_ca_crt.pl?name=coreca');
$hr = system(' openssl verify  -crl_check -CRLfile ./test/ca/coreca/coreca_crl.pem'
            .' -CAfile ./test/ca/coreca/coreca.crt'
            .' ./test/ca/coreca/01.pem');
goto myclose unless ( $hr == 0 );
say '---------------------------------------------------------------------------';
$hr = system('curl', '--fail', 'http://127.0.0.1:9090/get_ca_crt.pl?name=coreca&mode=shell');
goto myclose unless ($hr == 0);
$hr = system(' openssl verify  -crl_check -CRLfile ./test/ca/coreca/coreca_crl.pem'
            .' -CAfile ./test/ca/coreca/coreca.crt'
            .' ./test/ca/coreca/01.pem');
goto myclose unless ( $hr == 0 );
$hr = system(' openssl verify  -crl_check -CRLfile ./test/ca/coreca/coreca_crl.pem'
            .' -CAfile ./test/ca/coreca/coreca.crt'
            .' ./test/ca/coreca/01.pem');
goto myclose unless ( $hr == 0 );
$hr = system('curl', '--fail', 'http://127.0.0.1:9090/get_ca_crt.pl?name=sdsadad&mode=shell');
goto myclose unless ($hr != 0);
$hr = system(' openssl verify  -crl_check -CRLfile ./test/ca/coreca/coreca_crl.pem'
            .' -CAfile ./test/ca/coreca/coreca.crt'
            .' ./test/ca/coreca/01.pem');
goto myclose unless ( $hr == 0 );
$hr = system(' openssl verify  -crl_check -CRLfile ./test/ca/coreca/coreca_crl.pem'
            .' -CAfile ./test/ca/coreca/coreca.crt'
            .' ./test/ca/coreca/01.pem');
goto myclose unless ( $hr == 0 );
say '---------------------------------------------------------------------------';
$hr = system('curl', '--fail', 'http://127.0.0.1:9090/get_ca_crt.pl?name=coreca&mode=body&format=lolol');
goto myclose unless ($hr != 0);
$hr = system(' openssl verify  -crl_check -CRLfile ./test/ca/coreca/coreca_crl.pem'
            .' -CAfile ./test/ca/coreca/coreca.crt'
            .' ./test/ca/coreca/01.pem');
goto myclose unless ( $hr == 0 );
$hr = system('curl', '--fail', 'http://127.0.0.1:9090/get_ca_crt.pl?name=coreca&mode=body&format=pem');
goto myclose unless ($hr == 0);
$hr = system('curl', '--fail', 'http://127.0.0.1:9090/get_ca_crt.pl?name=coreca&mode=body&format=cert');
goto myclose unless ($hr == 0);
say '===========================================================================';
say 'CRL';
$hr = system('curl', '--fail', 'http://127.0.0.1:9090/get_crl.pl?name=coreca&mode=body&format=pem');
goto myclose unless ($hr == 0);
$hr = system(' openssl verify  -crl_check -CRLfile ./test/ca/coreca/coreca_crl.pem'
            .' -CAfile ./test/ca/coreca/coreca.crt'
            .' ./test/ca/coreca/01.pem');
goto myclose unless ( $hr == 0 );
system('curl', 'http://127.0.0.1:9090/create.pl?name=stuff&state=CA&cert_valid_time=2');
goto myclose unless ( -d './test/ca/stuff' );
$hr = system('curl', '--fail', 'http://127.0.0.1:9090/get_crl.pl?name=coreca,stuff,failed&mode=body&format=pem');
goto myclose unless ($hr == 0);
say '---------------------------------------------------------------------------';
my $ssl_client_cert = encode_base64 ( lf('./test/ca/coreca/01.pem'), undef );
chomp $ssl_client_cert;
my $ssl_client_s_dn = encode_base64('C=FR/ST=CA/O=Citypassenger/OU=MobileIT/CN=init', undef);
chomp $ssl_client_s_dn;
my $ssl_client_i_dn = encode_base64('C=FR/ST=CA/L=Paris/O=Citypassenger/OU=MobileIT/CN=coreca/emailAddress=support@citypassenger.com', undef); #ssl_client_i_dn
say '===========================================================================';
say 'auth';
say '---------------------------------------------------------------------------';
$hr = getheader ( ['Exists'], ['0']
          , 'curl', '-D-', '-d', 'certificate='.$ssl_client_s_dn
                                   .":".$ssl_client_i_dn
                                   .":".$ssl_client_cert
      , 'http://127.0.0.1:9090/ca/is_cert.pl?name=xxx');
say Dumper($hr);
@x = grep /OK/, @$hr;
say '===========================================================================';
say 'CREATE CERT';
say '---------------------------------------------------------------------------';

system('curl', '-d', 'certificate='.$ssl_client_s_dn
                                   .":".$ssl_client_i_dn
                                   .":".$ssl_client_cert
      , 'http://127.0.0.1:9090/ca/new_crt.pl?name=commonname');
$hr = system(' openssl verify  -crl_check -CRLfile ./test/ca/coreca/coreca_crl.pem'
            .' -CAfile ./test/ca/coreca/coreca.crt'
            .' ./test/ca/coreca/02.pem');
goto myclose unless ( $hr == 0 );
say '===========================================================================';
say 'RECREATE CERT';
say '---------------------------------------------------------------------------';
$hr = system('curl', '--fail', '-d', 'certificate='.$ssl_client_s_dn
                                   .":".$ssl_client_i_dn
                                   .":".$ssl_client_cert
      , 'http://127.0.0.1:9090/ca/new_crt.pl?name=commonname');
goto myclose unless ( $hr != 0 );
say '---------------------------------------------------------------------------';
system('curl', '-d', 'certificate='.$ssl_client_s_dn
                                   .":".$ssl_client_i_dn
                                   .":".$ssl_client_cert
      , 'http://127.0.0.1:9090/ca/new_crt.pl?name=commonadmin&admin=1');
$hr = system(' openssl verify  -crl_check -CRLfile ./test/ca/coreca/coreca_crl.pem'
            .' -CAfile ./test/ca/coreca/coreca.crt'
            .' ./test/ca/coreca/03.pem');
goto myclose unless ( $hr == 0 );
$hr = system(' grep -w commonadmin ./test/ca/coreca/admins');
goto myclose unless ( $hr == 0 );

say '---------------------------------------------------------------------------';
# FIXME

system('openssl req -batch -config ./test/ca/coreca/confssl.conf -new -newkey rsa:2048 -nodes -keyout stuff.key -out ./stuff.csr');

my $csrfile = encode_base64 lf('./stuff.csr'); #because + is valid and not in http
system('curl', '-d', 'certificate='.$ssl_client_s_dn
                                   .":".$ssl_client_i_dn
                                   .":".$ssl_client_cert
      , '-d', 'csr='.$csrfile
      , '-d', 'csr_format=pem'
      , 'http://127.0.0.1:9090/ca/new_crt_with_csr.pl?');
$hr = system(' openssl verify  -crl_check -CRLfile ./test/ca/coreca/coreca_crl.pem'
            .' -CAfile ./test/ca/coreca/coreca.crt'
            .' ./test/ca/coreca/04.pem');
goto myclose unless ( $hr == 0 );


say '===========================================================================';
say 'auth';
say '---------------------------------------------------------------------------';
$hr = getheader ( ['Exists'], ['0']
          , 'curl', '-D-', '-d', 'certificate='.$ssl_client_s_dn
                                   .":".$ssl_client_i_dn
                                   .":".$ssl_client_cert
      , 'http://127.0.0.1:9090/ca/is_cert.pl?name=xxx');
say Dumper($hr);
@x = grep /OK/, @$hr;
goto myclose unless ( scalar @x eq @$hr and scalar @x > 0 );
say '---------------------------------------------------------------------------';
$hr = getheader ( ['Exists'], ['1']
          , 'curl', '-D-', '-d', 'certificate='.$ssl_client_s_dn
                                   .":".$ssl_client_i_dn
                                   .":".$ssl_client_cert
      , 'http://127.0.0.1:9090/ca/is_cert.pl?name=commonname');
say Dumper($hr);
@x = grep /OK/, @$hr;
goto myclose unless ( scalar @x eq @$hr and scalar @x > 0 );
say '---------------------------------------------------------------------------';
my $cmd = join " ", ('curl', '-d', '"certificate='.$ssl_client_s_dn
                                   .":".$ssl_client_i_dn
                                   .":".$ssl_client_cert.'"'
      , '\'http://127.0.0.1:9090/ca/is_cert.pl?name=commonadmin&mode=body\'');
$hr = `$cmd`;
chomp $hr;
goto myclose unless ( $hr eq 'true' );
say '---------------------------------------------------------------------------';
$hr = system('curl', '-d', 'certificate='.$ssl_client_s_dn
                                   .":".$ssl_client_i_dn
                                   .":".$ssl_client_cert
      , '--fail', 'http://127.0.0.1:9090/ca/is_cert.pl?name=commonname&mode=shell');
goto myclose unless ( $hr == 0 );
say '---------------------------------------------------------------------------';
$hr = system('curl', '-d', 'certificate='.$ssl_client_s_dn
                                   .":".$ssl_client_i_dn
                                   .":".$ssl_client_cert
      , '--fail', 'http://127.0.0.1:9090/ca/is_cert.pl?name=xdfsgs&mode=shell');
goto myclose unless ( $hr != 0 );
# say '---------------------------------------------------------------------------';
$cmd = join " ", ('curl', '-d', '"certificate='.$ssl_client_s_dn
                                   .":".$ssl_client_i_dn
                                   .":".$ssl_client_cert.'"'
             , '"http://127.0.0.1:9090/ca/auth.pl"'); #FIXME

$hr = `$cmd`;
chomp $hr;
goto myclose unless ( $hr eq '{"admin":1}' );
say '===========================================================================';
say 'revoke';
say '---------------------------------------------------------------------------';
system('curl', '-d', 'certificate='.$ssl_client_s_dn
                                   .":".$ssl_client_i_dn
                                   .":".$ssl_client_cert
      , 'http://127.0.0.1:9090/ca/revoke.pl?name=commonname');

$hr = system('grep -w CN=commonname ./test/ca/coreca/index.txt | grep \'^R\'');
goto myclose unless ( $hr == 0 );
say '===========================================================================';
say 'delete ca';
say '---------------------------------------------------------------------------';
exit 0 if (defined $ARGV[0] and $ARGV[0] eq '-dd');
system('curl', '-d', 'certificate='.$ssl_client_s_dn
                                   .":".$ssl_client_i_dn
                                   .":".$ssl_client_cert
      , 'http://127.0.0.1:9090/ca/close.pl?name=coreca') unless (defined $ARGV[1] and $ARGV[1] eq '-d');
goto myclose if ( -d './test/ca/coreca' );
unlink 'stuff.csr', 'stuff.key';
say '===========================================================================';

say "\033[31;32m".'SUCCESS'."\033[0m";
goto allok;
myclose:
say "\033[31;1m".'ERROR'."\033[0m";
allok:
exit 0 if (defined $ARGV[0] and $ARGV[0] eq '-d');
say 'shutdown';
system('curl', 'http://127.0.0.1:9090/shutdown');

wait;

system('rm', '-rf', './test');
