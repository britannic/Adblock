#!/usr/bin/env perl
#

use strict;
use warnings;
use HTTP::Tiny;
my $http = HTTP::Tiny->new(verify_SSL => 1);
my $response;

die "URL required\n $0 \'<web URL>\'" unless @ARGV > 0;
# get a single page
$response = $http->get($ARGV[0]);
# die "Failed to retrieve $ARGV[0]!\n" unless $response->{success};
print $response->{content};
