package cws::ext;

use strict;
use warnings;
use Data::Dumper;
use v5.10;
use cws;

###
# Role api for ACL like bind to ca
###
sub setpolicy($) {
  my $r = shift @_;
}
sub check_input_cn($) {
  my $r = shift @_;
}
sub check_role_request($) {
  my $r = shift @_;
}
sub addrole($) {
  my $r = shift @_;
}
sub remrole($) {
  my $r = shift @_;
}
sub isrole($) {
  my $r = shift @_;
}
sub getrole($) {
  my $r = shift @_;
}
##
# Token api for SSO
##
sub get_token($) {
  my $r = shift @_;
}
sub check_token($) {
  my $r = shift @_;
}

1;