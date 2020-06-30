TODO:

revoke as a list
option to sign the new ca with root certif.

Setup:

|| bsd			||	linux					||
|| pkg_add fcgi nginx	||	apt-get install nginx libcgi-fast-perl	||

include root.nginx in your nginx conf
modify the server name to listen outside

test
perl -e "use CGI::Fast qw(:standard); print 'ok';"
ok
nginx -v
nginx version: nginx/1.6.0

