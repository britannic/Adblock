#!/usr/bin/env perl
#
# **** License ****
#
# Copyright (C) 2018 by Helm Rock Consulting
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
# Author: Neil Beadle
# Description: This script creates dnsmasq configuration files to redirect dns
# look ups to alternative IPs (blackholes, pixel servers etc.)
# USE AT YOUR OWN RISK!
#

use File::Basename;
use Getopt::Long;
use lib q{/opt/vyatta/share/perl5};
use lib q{/config/lib/perl};
use Sys::Syslog qw(:standard :macros);
use threads;
use v5.14;

# use strict;
# use warnings;
use EdgeOS::DNS::Blacklist (
  qw{
    $c
    $FALSE
    $NAME
    $TRUE
    $VERSION
    delete_file
    get_cfg_actv
    get_cfg_file
    get_cols
    get_file
    get_url
    is_admin
    is_configure
    log_msg
    pad_str
    process_data
    write_file
    }
);
delete $ENV{PATH};
my ( $cfg_file, $show );
my $cols = get_cols();

############################### script runs here ###############################
exit if &main();
exit 1;
################################################################################

# Set up command line options
sub get_options {
  my $input = shift;
  my @opts  = (
    [
      q{-f <file> # load a configuration file},
      q{f=s} => \$cfg_file
    ],
    [
      q{-help     # show help and usage text},
      q{help} => sub { usage( { option => q{help}, exit_code => 0 } ) }
    ],
    [ q{-v        # verbose output}, q{v} => \$show ],
    [
      q{-version  # show program version number},
      q{version} => sub { usage( { option => q{version}, exit_code => 0 } ) }
    ],
  );

  return \@opts if $input->{option};

  # Read command line flags and exit with help message if any are unknown
  return GetOptions( map { my $options = $_; (@$options)[ 1 .. $#$options ] }
      @opts );
  return;
}

# This is the main function
sub main {
  my $dnsmasq_svc = q{/etc/init.d/dnsmasq};
  my $cfg         = {
    disabled => 0,
    dmasq_d  => q{/etc/dnsmasq.d},
    flg_lvl  => 5,
    flg_file => q{/var/log/update-dnsmasq-flagged.cmds},
    log_name => q{update-dnsmasq},
    no_op    => q{/tmp/.update-dnsmasq.no-op},
    domains  => {
      duplicates => 0,
      icount     => 0,
      records    => 0,
      target     => q{address},
      type       => q{domains},
      unique     => 0,
    },
    hosts => {
      duplicates => 0,
      icount     => 0,
      records    => 0,
      target     => q{address},
      type       => q{hosts},
      unique     => 0,
    },
  };

  # Get command line options or print help if no valid options
  get_options() or usage( { option => q{help}, exit_code => 1 } );

  # Find reasons to quit
  exit 0 if ( -e $cfg->{no_op} );    # If the no_op file exists, exit.

  usage( { option => q{sudo}, exit_code => 1 } ) if not is_admin();
  usage( { option => q{cfg_file}, exit_code => 1 } )
    if defined $cfg_file && !-e $cfg_file;

  # Start logging
  openlog( $cfg->{log_name}, q{}, LOG_DAEMON );
  log_msg(
    {
      cols    => $cols,
      eof     => qq{\n},
      logsys  => q{},
      msg_str => qq{Starting } . basename($0) . qq{ v${VERSION}},
      msg_typ => q{INFO},
      show    => $show,
    }
  );

  # Make sure localhost is always in the exclusions whitelist
  $cfg->{hosts}->{exclude}->{localhost} = 1;

  # Now choose which data set will define the configuration
  my $success
    = defined $cfg_file
    ? get_cfg_file( { config => $cfg, file => $cfg_file } )
    : get_cfg_actv( { config => $cfg, show => $show } );

  # Now proceed if blacklist is enabled
  if ( !$cfg->{disabled} ) {
    my @areas = ();

    # Add areas to process only if they contain sources and copy global excludes
    for my $area (qw{domains hosts}) {
      push @areas => $area if scalar keys %{ $cfg->{$area}->{src} };
    }

    # Process each area
#     my $area_count = (@areas);
    for my $area (@areas) {
      my ( $prefix, @threads );
      my $max_thrds = 8;
      my @sources   = keys %{ $cfg->{$area}->{src} };
      while ( my ( $key, $value ) = each %{ $cfg->{exclude} } ) {
        $cfg->{$area}->{exclude}->{$key} = $value;
      }
      $cfg->{$area}->{icount} = scalar keys %{ $cfg->{$area}->{blklst} } // 0;
      @{ $cfg->{$area} }{qw{records unique}}
        = @{ $cfg->{$area} }{qw{icount icount}};

      # Remove any files that no longer have configured sources
      my $sources_ref = {
        map {
          my $key = $_;
          qq{$cfg->{dmasq_d}/$area.$key.blacklist.conf} => 1;
          } @sources
      };

      my $files_ref = { map { my $key = $_; $key => 1; }
          glob qq{$cfg->{dmasq_d}/$area.*blacklist.conf} };

      for my $file ( keys $files_ref ) {
        delete_file( { file => $file } )
          if !exists $sources_ref->{$file} && $file;
      }

      # write each configured area's includes into individual dnsmasq files
      if ( $cfg->{$area}->{icount} > 0 ) {
        my $equals = $area ne q{domains} ? q{=/} : q{=/.};
        write_file(
          {
            data => [
              map {
                my $value = $_;
                sprintf(
                  qq{%s%s%s/%s\n} => $cfg->{$area}->{target} => $equals,
                  $value, $cfg->{$area}->{dns_redirect_ip}
                );
                } sort keys %{ $cfg->{$area}->{blklst} }
            ],
            file => qq{$cfg->{dmasq_d}/$area.pre-configured.blacklist.conf},
          }
        );
      }

    NEXT:
      for my $source (@sources) {
        my ( $file, $url )
          = @{ $cfg->{$area}->{src}->{$source} }{ q{file}, q{url} };

        # Initialize the sources counters
        @{ $cfg->{$area}->{src}->{$source} }
          {qw(duplicates icount records unique)} = ( 0, 0, 0, 0 );

        $prefix
          = $cfg->{$area}->{src}->{$source}->{prefix} ~~ q{http}
          ? qr{(?:\A(?:http:|https:){1}[/]{1,2})}om
          : $cfg->{$area}->{src}->{$source}->{prefix};

        my $host;
        if ($url) {
          my $uri = new URI($url);
          $host = $uri->host;
          if ( not( $uri->scheme eq 'http' || $uri->scheme eq 'https' ) ) {
            log_msg(
              {
                cols    => $cols,
                logsys  => q{},
                msg_str => sprintf(
                  q{%s URL: %s incorrectly formatted} => $area,
                  $host
                ),
                msg_typ => q{ERROR},
                show    => $show,
              }
              )
              if $show;
            next NEXT;
          }

          log_msg(
            {
              cols    => $cols,
              logsys  => q{},
              msg_str => sprintf(
                q{Downloading %s blacklist from %s}, $area,
                $host
              ),
              msg_typ => q{INFO},
              show    => $show,
            }
            )
            if $show;

          push @threads => threads->create(
            { context => q{list}, exit => q{thread_only} },
            \&get_url,
            {
              area   => $area,
              host   => $host,
              prefix => $prefix,
              src    => $source,
              url    => $url
            }
          );
        }
        elsif ($file) {    # get file data
          $host = $source;
          push @threads => threads->create(
            { context => q{list}, exit => q{thread_only} },
            \&get_file,
            {
              area   => $area,
              host   => $host,
              file   => $file,
              prefix => $prefix,
              src    => $source
            }
          );
        }
        sleep 1 while ( scalar threads->list(threads::running) >= $max_thrds );
      }

      for my $thread (@threads) {
        my $data = $thread->join();
        if ( $data->{file} ) {
          $data->{data}
            = { map { my $key = $_; lc($key) => 1 } @{ $data->{data} } };
        }

        my $rec_count = scalar keys %{ $data->{data} } // 0;
        $cfg->{$area}->{src}->{ $data->{src} }->{records} += $rec_count;

        if ( exists $data->{host} && scalar $rec_count ) {
          log_msg(
            {
              cols    => $cols,
              logsys  => q{},
              msg_str => sprintf(
                q{%s lines received from: %s } => $rec_count,
                $data->{host}
              ),
              msg_typ => q{INFO},
              show    => $show,
            }
          );

          # Now process what we have received from the web host
          process_data(
            {
              area   => $area,
              cols   => $cols,
              config => $cfg,
              data   => \%{ $data->{data} },
              prefix => $data->{prefix},
              show   => $show,
              src    => $data->{src}
            }
          );

          # Delete $data->{data} key and data
          delete $data->{data};

          # Write blacklist to file, change to domain format if area = domains
          my $file = qq{$cfg->{dmasq_d}/$area.$data->{src}.blacklist.conf};
          if ( keys %{ $cfg->{$area}->{src}->{ $data->{src} }->{blklst} }
            and $data->{success} )
          {
            my $equals = $area ne q{domains} ? q{=/} : q{=/.};
            write_file(
              {
                data => [
                  map {
                    my $value = $_;
                    sprintf(
                      qq{%s%s%s/%s\n} => $cfg->{$area}->{target},
                      $equals, $value,
                      $cfg->{$area}->{src}->{ $data->{src} }->{dns_redirect_ip}
                    );
                    } sort
                    keys %{ $cfg->{$area}->{src}->{ $data->{src} }->{blklst} }
                ],
                file => $file,
              }
            );

            # Compute statistics
            $cfg->{$area}->{unique}
              += scalar
              keys %{ $cfg->{$area}->{src}->{ $data->{src} }->{blklst} };
            $cfg->{$area}->{duplicates}
              += $cfg->{$area}->{src}->{ $data->{src} }->{duplicates};
            $cfg->{$area}->{icount}
              += $cfg->{$area}->{src}->{ $data->{src} }->{icount};
            $cfg->{$area}->{records}
              += $cfg->{$area}->{src}->{ $data->{src} }->{records};

            # Discard the data now its written to file
            delete $cfg->{$area}->{src}->{ $data->{src} };
          }
          else {
            my @data = (
              sprintf(
                    qq{# No data received\n# HTTP Status: %s\n# Reason: %s\n}
                  . qq{# Content: %s\n} => @{$data}{qw{status reason}}
              )
            );
            write_file(
              {
                data => \@data,
                file => $file,
              }
            );
            log_msg(
              {
                cols    => $cols,
                eof     => qq{\n},
                logsys  => q{},
                msg_str => qq{Zero records processed from $data->{src}!},
                msg_typ => q{WARNING},
                show    => $show,
              }
            );
          }
        }
      }

      log_msg(
        {
          cols   => $cols,
          logsys => sprintf(
            qq{Processed %s %s (%s rejects) from %s (%s orig.) lines},
            @{ $cfg->{$area} }{qw(unique type duplicates icount records)}
          ),
          msg_str => sprintf(
            qq{Processed $c->{grn}%s$c->{clr} %s ($c->{red}%s$c->{clr} }
              . qq{rejected) from $c->{mag}%s$c->{clr} (%s orig.) lines%s},
            @{ $cfg->{$area} }{qw(unique type duplicates icount records)},
            qq{\n}
          ),
          msg_typ => q{INFO},
          show    => $show,
        }
      );

      # Now lets report the domains that exceeded $cfg->{flg_lvl}
      my @flagged_domains;
      for my $key (
        sort {
          $cfg->{hosts}->{exclude}->{$b} <=> $cfg->{hosts}->{exclude}->{$a}
        } sort keys %{ $cfg->{hosts}->{exclude} }
        )
      {
        my $value = $cfg->{hosts}->{exclude}->{$key};
        if ( $value >= $cfg->{flg_lvl} && length $key > 5 ) {
          log_msg(
            {
              cols    => $cols,
              eof     => qq{\n},
              logsys  => q{},
              msg_str => sprintf(
                qq{$area blacklisted: domain %s %s times} => $key,
                $value
              ),
              msg_typ => q{INFO},
              show    => $show,
            }
          );
          push @flagged_domains => qq{$key # $value times};
        }
      }

      if (@flagged_domains) {
        write_file(
          {
            data => [
              map {
                my $value = $_;
                sprintf(
                  qq{set service dns forwarding blacklist domains include %s\n}
                    => $value );
                } @flagged_domains
            ],
            file => $cfg->{flg_file},
          }
        );

        log_msg(
          {
            cols   => $cols,
            eof    => qq{\n},
            logsys => q{},
            msg_str =>
              qq{Wrote flagged domains to: $cfg->{flg_file}},
            msg_typ => q{INFO},
            show    => $show,
          }
        );
      }

#       $area_count--;
#       say q{} if ( $area_count == 1 && $show );    # print a final line feed
    }
  }
  elsif ( $cfg->{disabled} ) {
    my $conf_state = !$success ? q{isn't configured} : q{is disabled};

    log_msg(
      {
        cols   => $cols,
        eof    => qq{\n},
        logsys => q{},
        msg_str =>
          qq{$NAME $VERSION $conf_state...},
        msg_typ => q{INFO},
        show    => $show,
      }
    );

    for my $file ( glob qq{$cfg->{dmasq_d}/{domains,hosts}*blacklist.conf} ) {
      log_msg(
        {
          cols   => $cols,
          eof    => qq{\n},
          logsys => q{},
          msg_str =>
            qq{Removing $file},
          msg_typ => q{INFO},
          show    => $show,
        }
      );
      delete_file( { file => $file } ) if $file;
    }
  }

  # Clean up the status line
  print $c->{off}, qq{\r}, pad_str(), qq{\r} if ( $show && !$cfg->{disabled} );

#   say q{} if $show;    # print a final line feed

  log_msg(
    {
      cols    => $cols,
      eof     => qq{\n},
      logsys  => q{},
      msg_str => q{Reloading dnsmasq configuration...},
      msg_typ => q{INFO},
      show    => $show,
    }
  );

  # Reload updated dnsmasq conf address redirection files. Have to use /dev/null
  # twice as >/dev/null 2>&1 doesn't work - writes "1" to current directory
  qx{$dnsmasq_svc force-reload 1>/dev/null 2>/dev/null};

  log_msg(
    {
      cols    => $cols,
      eof     => qq{\n},
      logsys  => q{},
      msg_str => q{Reloading dnsmasq configuration failed},
      msg_typ => q{ERROR},
      show    => $show,
    }
    )
    if ( $? >> 8 != 0 );

  # Close the log
  closelog();

  # Finish with a linefeed if '-v' is selected
  print $c->{on}, q{} if $show;
}

# Process command line options and print usage
sub usage {
  my $input    = shift;
  my $progname = basename($0);
  my $usage    = {
    cfg_file => sub {
      my $exitcode = shift;
      print STDERR
        qq{$cfg_file not found, check path and file name is correct\n};
      exit $exitcode;
    },
    help => sub {
      my $exitcode = shift;
      local $, = qq{\n};
      print STDERR @_;
      print STDERR qq{usage: $progname <options>\n};
      print STDERR q{options:},
        map( q{ } x 4 . $_->[0],
        sort { $a->[1] cmp $b->[1] } grep $_->[0] ne q{},
        @{ get_options( { option => $TRUE } ) } ),
        qq{\n};
      $exitcode == 1 ? return $TRUE : exit $exitcode;
    },
    sudo => sub {
      my $exitcode = shift;
      print STDERR qq{This script must be run as root, use: sudo $0.\n};
      exit $exitcode;
    },
    version => sub {
      my $exitcode = shift;
      printf STDERR qq{%s version: %s\n}, $progname, $VERSION;
      exit $exitcode;
    },
  };

  # Process option argument
  $usage->{ $input->{option} }->( $input->{exit_code} );
}

