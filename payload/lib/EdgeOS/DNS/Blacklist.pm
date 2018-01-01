# Copyright (C) 2017 by Helm Rock Consulting
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# **** End License ****
#
#
# Author: Neil Beadle
# Description: Perl Library for creating dnsmasq configuration files to
# redirect dns look ups to alternative IPs (blackholes, pixel servers etc.)

package EdgeOS::DNS::Blacklist;
use parent qw(Exporter);    # imports and subclasses Exporter
use base qw(Exporter);
use v5.14;

# use strict;
# use warnings;
use lib q{/opt/vyatta/share/perl5/};
use File::Basename;
use Getopt::Long;
use Term::Cap;
use HTTP::Tiny;
use Net::Nslookup;
use POSIX qw{geteuid getegid getgroups};
use Socket (
  qw{
    AF_INET
    getaddrinfo
    getnameinfo
    inet_ntop
    unpack_sockaddr_in
    unpack_sockaddr_in6
    }
);
use Sys::Syslog qw(:standard :macros);
use Term::ReadKey qw(GetTerminalSize);
use threads;
use URI;
use Vyatta::Config;

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration use EdgeOS::DNS::Blacklist ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
# our %EXPORT_TAGS = ( 'all' => [qw()] );
our @EXPORT_OK = (
  qw{
    $c
    $FALSE
    $NAME
    $spoke
    $tcap
    $TRUE
    $VERSION
    clear_end
    clear_screen
    delete_file
    get_cfg_actv
    get_cfg_file
    get_cols
    get_dev_stats
    get_file
    get_ip
    get_url
    get_user
    gotoxy
    is_admin
    is_build
    is_configure
    is_version
    log_msg
    $maxcol
    $maxrow
    pad_str
    pinwheel
    popx
    process_data
    set_dev_grp
    term_end
    term_init
    write_file
    }
);
our $NAME    = q{dnsmasq_blklist};
our $VERSION = q{3.7.3};
our $TRUE;
*TRUE = \1;
our $FALSE;
*FALSE = \0;
our $c = {
  blk        => qq{\033[30m},
  blink      => qq{\033[5m},
  blu        => qq{\033[34m},
  clr        => qq{\033[0m},
  deleol     => qq{\033[K},
  grn        => qq{\033[92m},
  mag        => qq{\033[95m},
  off        => qq{\033[?25l},
  on         => qq{\033[?25h},
  red        => qq{\033[91m},
  reverse    => qq{\033[7m},
  ulineon    => qq{\033[4m},
  ulineoff   => qq{\033[24m},
  underscore => qq{\033[4m},
  wyt        => qq{\033[37m},
  ylw        => qq{\033[93m},
};
our $spoke;
our @EXPORT;
our $tcap;
our ( $maxrow, $maxcol ) = ( $tcap->{_li} - 1, $tcap->{_co} - 1 );

# our $maxrow;

# Initialize Term::Cap.
sub term_init {
  $| = 1;                                         # Turn on buffer auto flushing
  $tcap = Term::Cap->Tgetent( { TERM => undef } );
  $tcap->Trequire(qw(cl cm cd));
  ( $maxrow, $maxcol ) = ( $tcap->{_li} - 1, $tcap->{_co} - 1 );
}

# clear_screen clears the entire screen
sub clear_screen { $tcap->Tputs( 'cl', 1, *STDOUT ) }

# clear_end clears to the end of the screen.
sub clear_end { $tcap->Tputs( 'cd', 1, *STDOUT ) }

# Move the cursor to a specified location.
sub gotoxy {
  my ( $x, $y ) = @_;
  $tcap->Tgoto( 'cm', $x, $y, *STDOUT );
}

# Clear the screen from x to y coordinates.
sub term_end {
  my ( $x, $y ) = @_;
  gotoxy( $x, $y );
  clear_end();
}

# Erase to end of line
sub pad_str {
  my $str = shift // $c->{deleol};

  return sprintf( "%s%s", $str, $c->{deleol} );
}

# Does just what it says
sub delete_file {
  my $input = shift;

  if ( -e $input->{file} ) {
    log_msg(
      {
        logsys  => q{},
        msg_typ => q{INFO},
        msg_str => qq{Deleting file $input->{file}},
      }
    );
    unlink $input->{file};
  }

  if ( -e $input->{file} ) {
    log_msg(
      {
        logsys  => q{},
        msg_typ => q{WARNING},
        msg_str => qq{Unable to delete $input->{file}},
      }
    );
    return;
  }
  return $TRUE;
}

# Process the active configuration
sub get_cfg_actv {
  my $config       = new Vyatta::Config;
  my $input        = shift;
  my $exists       = q{existsOrig};
  my $listNodes    = q{listOrigNodes};
  my $returnValue  = q{returnOrigValue};
  my $returnValues = q{returnOrigValues};

  if ( is_configure() ) {
    $exists       = q{exists};
    $listNodes    = q{listNodes};
    $returnValue  = q{returnValue};
    $returnValues = q{returnValues};
  }

# Check to see if blacklist is configured
  $config->setLevel(q{service dns forwarding});
  my $blklst_exists = $config->$exists(q{blacklist}) ? $TRUE : $FALSE;

  if ($blklst_exists) {
    $config->setLevel(q{service dns forwarding blacklist});
    $input->{config}->{disabled} = $config->$returnValue(q{disabled}) // $FALSE;
    $input->{config}->{dns_redirect_ip}
      = $config->$returnValue(q{dns-redirect-ip}) // q{0.0.0.0};

    for my $key ( $config->$returnValues(q{exclude}) ) {
      $input->{config}->{exclude}->{$key} = 1;
    }

    $input->{config}->{disabled}
      = $input->{config}->{disabled} eq q{false} ? $FALSE : $TRUE;

    for my $area (qw{hosts domains}) {
      $config->setLevel(qq{service dns forwarding blacklist $area});
      $input->{config}->{$area}->{dns_redirect_ip}
        = $config->$returnValue(q{dns-redirect-ip})
        // $input->{config}->{dns_redirect_ip};

      for my $key ( $config->$returnValues(q{include}) ) {
        $input->{config}->{$area}->{blklst}->{$key} = 1;
      }

      for my $key ( $config->$returnValues(q{exclude}) ) {
        $input->{config}->{$area}->{exclude}->{$key} = 1;
      }

      if ( !keys %{ $input->{config}->{$area}->{exclude} } ) {
        $input->{config}->{$area}->{exclude} = {};
      }

      if ( !keys %{ $input->{config}->{exclude} } ) {
        $input->{config}->{exclude} = {};
      }

      for my $source ( $config->$listNodes(q{source}) ) {
        $config->setLevel(
          qq{service dns forwarding blacklist $area source $source});
        @{ $input->{config}->{$area}->{src}->{$source} }
          {qw(description dns_redirect_ip file prefix url)} = (
          $config->$returnValue(q{description}),
          $config->$returnValue(q{dns-redirect-ip})
            // $input->{config}->{$area}->{dns_redirect_ip},
          $config->$returnValue(q{file}),
          $config->$returnValue(q{prefix}),
          $config->$returnValue(q{url})
          );
      }
    }
  }
  else {
    $input->{show} = $TRUE;
    log_msg(
      {
        logsys  => q{},
        show    => $input->{show},
        msg_typ => q{ERROR},
        msg_str =>
          q{[service dns forwarding blacklist is not configured], exiting!},
      }
    );
    return;
  }
  if ( ( !scalar keys %{ $input->{config}->{domains}->{src} } )
    && ( !scalar keys %{ $input->{config}->{hosts}->{src} } ) )
  {
    $input->{show} = $TRUE;
    log_msg(
      {
        logsys  => q{},
        show    => $input->{show},
        msg_typ => q{ERROR},
        msg_str => q{At least one domain or host online source/file }
          . q{must be configured},
      }
    );
    return;
  }
  return $TRUE;
}

# Process a configuration file in memory after get_file() loads it
sub get_cfg_file {
  my $input = shift;
  my $tmp_ref
    = get_nodes( { config_data => get_file( { file => $input->{file} } ) } );
  my $configured
    = ( $tmp_ref->{domains}->{source} || $tmp_ref->{hosts}->{source} )
    ? $TRUE
    : $FALSE;

  if ($configured) {
    $input->{config}->{dns_redirect_ip} = $tmp_ref->{q{dns-redirect-ip}}
      // q{0.0.0.0};
    $input->{config}->{disabled}
      = $tmp_ref->{disabled} eq q{false} ? $FALSE : $TRUE;
    $input->{config}->{exclude}
      = exists $tmp_ref->{exclude} ? $tmp_ref->{exclude} : ();

    for my $area (qw{hosts domains}) {

      $input->{config}->{$area}->{dns_redirect_ip}
        = $tmp_ref->{$area}->{q{dns-redirect-ip}}
        // $input->{config}->{dns_redirect_ip};

      for my $source ( $tmp_ref->{$area}->{src} ) {
        $input->{config}->{$area}->{src}->{$source}->{dns_redirect_ip}
          = $tmp_ref->{$area}->{src}->{$source}->{dns_redirect_ip}
          // $input->{config}->{$area}->{dns_redirect_ip};
      }
    }
  }
  else {
    $input->{show} = $TRUE;
    log_msg(
      {
        logsys  => q{},
        show    => $input->{show},
        msg_typ => q{ERROR},
        msg_str =>
          q{[service dns forwarding blacklist] isn't configured, exiting!},
      }
    );
    return;
  }
  return $TRUE;
}

# Try multiple ways to get terminal columns
sub get_cols {
  local $SIG{__WARN__} = sub {$TRUE};
  return ( ( GetTerminalSize( \*STDOUT ) )[0]
      || $ENV{COLUMNS}
      || qx{tput cols}
      || 80 );
}

# Get directory stats, user/group ownership
sub get_dev_stats {
  my $input = shift;
  my @attributes
    = (
    qw{dev inode mode nlink uid gid rdev size atime mtime ctime blksize blocks}
    );
  return
    print STDERR qq{Error: attribute must be one or more of "}
    . join( q{, } => @attributes ) . q{".}
    if !$input->{attribute} ~~ @attributes;
  @{ $input->{dev_stats} }{@attributes} = stat( $input->{dev} )
    or die $!;
  return $input->{dev_stats}->{ $input->{attribute} };
}

# Read a file into memory and return the data to the calling function
sub get_file {
  my $input = shift;
  if ( -e $input->{file} ) {
    open my $CF, q{<}, $input->{file}
      or die qq{[ERROR]: Unable to open $input->{file}: $!};
    chomp( @{ $input->{data} } = <$CF> );
    close $CF;
  }
  return $input;
}

# Build hashes from the configuration file data (called by get_nodes())
sub get_hash {
  my $input    = shift;
  my $hash     = \$input->{hash_ref};
  my @nodes    = @{ $input->{nodes} };
  my $value    = pop @nodes;
  my $hash_ref = ${$hash};

  for my $key (@nodes) {
    $hash = \${$hash}->{$key};
  }

  ${$hash} = $value if $value;
  return $hash_ref;
}

# Get an IP address from a hostname
sub get_ip {

  # Check to see if Net::NSLookup is present
#   my $nslookup = eval { require Net::Nslookup; 1 };
  my $addr;
  my $host   = shift;
  my $server = "127.0.0.1";
  my $ip     = nslookup( host => $host, server => $server, type => "A" );

  return $ip;

#   my ( $err, @getaddr ) = getaddrinfo( $host, 0 );
#
#   if ( $getaddr[0]->{family} == AF_INET ) {
#     return "" if length( $getaddr[0]->{addr} ) < 16;
#     $addr = unpack_sockaddr_in( $getaddr[0]->{addr} );
#     $ip = inet_ntop( AF_INET, $addr );
#   }
#   else {
#     return "" if length( $getaddr[0]->{addr} ) < 28;
#     $addr = unpack_sockaddr_in6( $getaddr[0]->{addr} );
#     $ip = inet_ntop( $getaddr[0]->{family}, $addr );
#   }
#   return $ip;
}

# Process a configure file and extract the blacklist data set
sub get_nodes {
  my $input = shift;
  my ( @hasher, @nodes );
  my $cfg_ref = {};
  my $leaf    = 0;
  my $level   = 0;
  my $re      = {
    BRKT => qr/[}]/o,
    CMNT => qr/^(?<LCMT>[\/*]+).*(?<RCMT>[*\/]+)$/o,
    DESC => qr/^(?<NAME>[\w-]+)\s"?(?<DESC>[^"]+)?"?$/o,
    MPTY => qr/^$/o,
    LEAF => qr/^(?<LEAF>[\w-]+)\s(?<NAME>[\S]+)\s[{]{1}$/o,
    LSPC => qr/\s+$/o,
    MISC => qr/^(?<MISC>[\w-]+)$/o,
    MULT => qr/^(?<MULT>(?:include|exclude)+)\s(?<VALU>[\S]+)$/o,
    NAME => qr/^(?<NAME>[\w-]+)\s(?<VALU>[\S]+)$/o,
    NODE => qr/^(?<NODE>[\w-]+)\s[{]{1}$/o,
    RSPC => qr/^\s+/o,
  };

LINE:
  for my $line ( @{ $input->{config_data}->{data} } ) {
    $line =~ s/$re->{LSPC}//;
    $line =~ s/$re->{RSPC}//;

    for ($line) {
      when (/$re->{MULT}/) {
        push( @nodes => $+{MULT}, $+{VALU}, 1 );
        get_hash( { nodes => \@nodes, hash_ref => $cfg_ref } );
        popx( @nodes, 3 );
      }
      when (/$re->{NODE}/) {
        push @nodes => $+{NODE};
      }
      when (/$re->{LEAF}/) {
        $level++;
        push( @nodes => $+{LEAF}, $+{NAME} );
      }
      when (/$re->{NAME}/) {
        push( @nodes => $+{NAME}, $+{VALU} );
        get_hash( { nodes => \@nodes, hash_ref => $cfg_ref } );
        popx( @nodes => 2 );
      }
      when (/$re->{DESC}/) {
        push( @nodes => $+{NAME}, $+{DESC} );
        get_hash( { nodes => \@nodes, hash_ref => $cfg_ref } );
        popx( @nodes => 2 );
      }
      when (/$re->{MISC}/) {
        push( @nodes => $+{MISC}, $+{MISC} );
        get_hash( { nodes => \@nodes, hash_ref => $cfg_ref } );
        popx( @nodes => 2 );
      }
      when (/$re->{CMNT}/) {
        next;
      }
      when (/$re->{BRKT}/) {
        pop @nodes;
        if ( $level > 0 ) {
          pop @nodes;
          $level--;
        }
      }
      when (/$re->{MPTY}/) {
        next LINE;
      }
      default {
        printf q{Parse error: "%s"}, $line;
      }
    }
  }
  return $cfg_ref->{service}->{dns}->{forwarding}->{blacklist};
}

# Get lists from web servers
sub get_url {
  my $input = shift;
  my $agent
    = q{Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11) AppleWebKit/601.1.56},
    q{ (KHTML, like Gecko ) Version / 9.0 Safari / 601.1.56};

  my $ua
    = HTTP::Tiny->new( agent => $agent, verify_SSL => 1 )->get( $input->{url} );

  $input->{prefix} =~ s/^["](?<UNCMT>.*)["]$/$+{UNCMT}/g;
  my $re = {
    REJECT => qr{\A#|\A\z|\A\n}oms,
    SELECT => qr{\A $input->{prefix} .*\z}xms,
    SPLIT  => qr{\R|<br \/>}oms,
  };

#   my $get = $ua->get( $input->{url} );

  if ( $ua->{success} ) {
    $input->{success} = 1;
    $input->{data}    = {
      map { my $key = $_; lc($key) => 1 }
        grep { $_ =~ /$re->{SELECT}/ } split /$re->{SPLIT}/,
      $ua->{content}
    };
    return $input;
  }
  else {
    log_msg(
      {
        logsys  => q{},
        msg_str => qq{get_url: $ua->{status}: $ua->{reason}: $ua->{content}},
        msg_typ => q{WARNING},
      }
    );
    $input->{data} = { 1 => $ua->{content} };
    @{$input}{qw{content reason status success}}
      = @{$ua}{qw{content reason status success}};
    return $input;
  }
}

# Get user & group IDs
sub get_user {
  my $input = shift // return;
  my $attributes = {
    gid  => getegid(),
    grps => [ getgroups() ],
    name => getlogin(),
    uid  => geteuid(),
  };
  return $attributes->{ $input->{attribute} };
}

# Make sure script runs as root
sub is_admin {
  return $TRUE if geteuid() == 0;
  return;
}

# Get build #
sub is_build {
  my $input = is_version();

  # ER-Lite
  # v1.2.0:           build 4574253
  # v1.4.1:           build 4648309
  # v1.5.0:           build 4677648
  # v1.6.0:           build 4716006
  # v1.7.0:           build 4783374
  # v1.8.0:           build 4853089
  # v1.8.5:           build 4884695
  # v1.9.0:           build 4901118
  # v1.9.1:           build 4939093
  # v1.9.1.1:         build 4977347
  # v1.9.7:           build 5001798
  # v1.9.7+hotfix:    build 5005851
  # v1.9.7+hotfix.2:  build 5001798
  # v1.9.7+hotfix.3:  build 5013619
  # v1.9.7+hotfix.4:  build 5024004

  # ER-X
  # v1.9.7+hotfix.4:  build 5024279

  # UniFi Security Gateway
  # v4.3.49:          build 5001153 USG
  # v4.4.8:           build 5023698 USG

  if ( $input->{build} >= 5001153 )    # script tested on os v1.7.0 & above
  {
    return $TRUE;
  }
  elsif ( $input->{build} < 4783374 )    # os must be upgraded
  {
    return;
  }
}

# Check to see if we are being run under configure
sub is_configure {
  qx{/bin/cli-shell-api inSession};
  return $? >> 8 != 0 ? $FALSE : $TRUE;
}

# get EdgeOS version
sub is_version {
  my @ver;
  my ( $build, $version ) = ( q{UNKNOWN BUILD}, q{UNKNOWN VERSION} );
  my $cmd = qq{cat /etc/version};
  chomp( my $edgeOS = qx{$cmd} );

  if ( @ver = split /\./ => $edgeOS ) {
    $version = join "." => @ver[ 0 .. $#ver - 3 ];
    $build = $ver[ $#ver - 2 ];
  }

  return { version => $version, build => $build };
}

# Log and print (if $show = $TRUE)
sub log_msg {
  $|++;
  my $input   = shift;
  my $len     = ( length $input->{msg_typ} . $input->{msg_str} );
  my $log_msg = {
    ALERT    => LOG_ALERT,
    CRITICAL => LOG_CRIT,
    DEBUG    => LOG_DEBUG,
    ERROR    => LOG_ERR,
    INFO     => LOG_NOTICE,
    WARNING  => LOG_WARNING,
  };

  return unless ( $len > 2 );

  $input->{eof} //= q{};

  if ( $input->{logsys} == q{} ) {
    syslog(
      $log_msg->{ $input->{msg_typ} },
      qq{[$input->{msg_typ}]: } . $input->{msg_str}
    );
  }
  else {
    syslog(
      $log_msg->{ $input->{msg_typ} },
      qq{[$input->{msg_typ}]: } . $input->{logsys}
    );
  }

  if ( $input->{msg_typ} eq q{INFO} ) {
    print $c->{off}, qq{\r},
      pad_str(qq{[$c->{grn}$input->{msg_typ}$c->{clr}]: $input->{msg_str}}),
      $input->{eof}
      if $input->{show};
  }
  else {
    print $c->{off}, qq{\r},
      pad_str(qq{[$c->{red}$input->{msg_typ}$c->{clr}]: $input->{msg_str}}),
      $input->{eof}
      if $input->{show};
  }

  $|--;
  return $TRUE;
}

# Create an animated activity spinner
sub pinwheel {
  my %wheel = ( q{|} => q{/}, q{/} => q{-}, q{-} => q{\\}, q{\\} => q{|}, );
  $spoke = ( not defined $spoke ) ? q{|} : $wheel{$spoke};
  return qq{\r[$c->{ylw}$spoke$c->{clr}]};
}

# pop array x times
sub popx (\@$) {
  my ( $array, $count ) = ( shift, shift );
  return if !@{$array};
  for ( 1 .. $count ) { pop @{$array}; }
  return $TRUE;
}

# Crunch the data and throw out anything we don't need
sub process_data {
  my $input = shift;
  my $re    = {
    FQDOMN =>
      qr{(\b(?:(?![.]|-)[\w-]{1,63}(?<!-)[.]{1})+(?:[a-zA-Z]{2,63})\b)}o,
    LSPACE => qr{\A\s+}oms,
    RSPACE => qr{\s+\z}oms,
    PREFIX => qr{\A $input->{prefix} }xms,
    SUFFIX => qr{(?:#.*|\{.*|[/[].*)\z}oms,
  };

  # Clear the status lines
  print $c->{off} => qq{\r}, qq{ } x $input->{cols}, qq{\r} if $input->{show};

# Process the lines we've been given
LINE:
  for my $line ( keys %{ $input->{data} } ) {
    next LINE if $line eq q{} || !defined $line;
    $line =~ s/$re->{PREFIX}|$re->{SUFFIX}//g;
    $line =~ s/$re->{LSPACE}|$re->{RSPACE}//g;

    # Get all of the FQDNs or domains in the line
    my @elements = $line =~ m/$re->{FQDOMN}/gc;
    next LINE if !scalar @elements;

    # We use map to individually pull 1 to N FQDNs or domains from @elements
    for my $element (@elements) {

      # Break it down into it components
      my @domain = split /[.]/ => $element;

      # Create an array of all the subdomains
      my @keys;
      for ( 2 .. @domain ) {
        push @keys, join q{.} => @domain;
        shift @domain;
      }

      # Have we seen this key before?
      my $key_exists = $FALSE;
      for my $key (@keys) {
        if ( exists $input->{config}->{ $input->{area} }->{exclude}->{$key} ) {
          $key_exists = $TRUE;
          $input->{config}->{ $input->{area} }->{exclude}->{$key}++;
        }
      }

      # Now add the key, convert to .domain.tld if only two elements
      if ( !$key_exists ) {
        $input->{config}->{ $input->{area} }->{src}->{ $input->{src} }
          ->{blklst}->{$element} = 1;
      }
      else {
        $input->{config}->{ $input->{area} }->{src}->{ $input->{src} }
          ->{duplicates}++;
      }

      # Add to the exclude list, so the next source doesnt duplicate values
      $input->{config}->{ $input->{area} }->{exclude}->{$element} = 1;
    }

    $input->{config}->{ $input->{area} }->{src}->{ $input->{src} }->{icount}
      += scalar @elements;

    printf
      qq{$c->{off}%s: $c->{grn}%s$c->{clr} %s processed, ($c->{red}%s$c->{clr} discarded) from $c->{mag}%s$c->{clr} lines\r},
      $input->{src},
      $input->{config}->{ $input->{area} }->{src}->{ $input->{src} }->{icount},
      $input->{config}->{ $input->{area} }->{type},
      @{ $input->{config}->{ $input->{area} }->{src}->{ $input->{src} } }
      { q{duplicates}, q{records} }
      if $input->{show};
  }

  if (
    scalar $input->{config}->{ $input->{area} }->{src}->{ $input->{src} }
    ->{icount} )
  {
    log_msg(
      {
        logsys => sprintf(
          qq{%s: %s %s processed, (%s discarded) from %s lines},
          $input->{src},
          $input->{config}->{ $input->{area} }->{src}->{ $input->{src} }
            ->{icount},
          $input->{config}->{ $input->{area} }->{type},
          @{ $input->{config}->{ $input->{area} }->{src}->{ $input->{src} } }
            { q{duplicates}, q{records} }
        ),
        msg_typ => q{INFO},
        msg_str => sprintf(
          qq{$c->{off}%s: $c->{grn}%s$c->{clr} %s processed, ($c->{red}%s$c->{clr} discarded) from $c->{mag}%s$c->{clr} lines\r},
          $input->{src},
          $input->{config}->{ $input->{area} }->{src}->{ $input->{src} }
            ->{icount},
          $input->{config}->{ $input->{area} }->{type},
          @{ $input->{config}->{ $input->{area} }->{src}->{ $input->{src} } }
            { q{duplicates}, q{records} }
        ),
      }
    );
    return $TRUE;
  }
  return;
}

# Fix active configuration directory group and user ownership
sub set_dev_grp {
  my $input = shift // return;
  my $dev_grp
    = get_dev_stats( { attribute => q{gid}, dev => $input->{dir_handle} } );
  if ( $dev_grp ~~ @{ $input->{grps} } ) {
    return $TRUE;
  }
  else {
    my $result
      = qx{sudo chgrp -R $input->{dir_grp} $input->{dir_handle}}
      ? $FALSE
      : $TRUE;
    return $result;
  }
}

# Write the data to file
sub write_file {
  my $input = shift;

  return if !@{ $input->{data} };

  open my $FH, q{>}, $input->{file} or return;
  log_msg(
    {
      logsys  => q{},
      msg_typ => q{INFO},
      msg_str => sprintf( q{Saving %s}, basename( $input->{file} ) ),
    }
  );

  print {$FH} @{ $input->{data} };
  close $FH;

  return $TRUE;
}

1;
__END__

=head1 Blacklist

EdgeOS::DNS::Blacklist - Perl extension for EdgeOS dnsmasq blacklist configuration file generation

=head1 SYNOPSIS

  use EdgeOS::DNS::Blacklist (qw{
    $c
    $FALSE
    $spoke
    $TRUE
    pad_str
    delete_file
    get_cfg_actv
    get_cfg_file
    get_cols
    get_dev_stats
    get_file
    get_url
    get_user
    is_admin
    is_build
    is_configure
    is_version
    log_msg
    pinwheel
    popx
    process_data
    set_dev_grp
    write_file

    });

=head1 DESCRIPTION

Module provides functions for creating dnsmasq configuration files to redirect
dns look ups to alternative IPs (blackholes, pixel servers etc.)

=head2 EXPORT

None by default.

=head1 SEE ALSO

http://community.ubnt.com/t5/EdgeMAX/CLI-Integrated-dnsmasq-Adblocking-amp-Blacklisting-v3-3-2-Easy/m-p/1344740#U1344740

=head1 AUTHOR

Neil Beadle

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2017 by Neil Beadle

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.23.4 or,
at your option, any later version of Perl 5 you may have available.


=cut
