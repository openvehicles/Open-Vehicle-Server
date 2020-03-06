#!/usr/bin/perl

use strict;
use warnings;
use Carp;

use EV;
use AnyEvent;
use AnyEvent::Log;
use AnyEvent::Debug;
use Digest::MD5;
use Digest::HMAC;
use Crypt::RC4::XS;
use MIME::Base64;
use JSON::XS;
use URI;
use URI::QueryParam;
use URI::Escape;

# Local plugin search directories

use lib 'plugins/local';
use lib 'plugins/system';

# Hard-coded Required plugins

use OVMS::Server::Core;
use OVMS::Server::Plugin;

my $core_mgr = new OVMS::Server::Core();

$AnyEvent::Log::FILTER->level (MyConfig()->val('log','level','info'));

my $info_tim = AnyEvent->timer (after => 10, interval => 10, cb => \&info_tim);

RegisterFunction('InfoCount',\&info_count);
my $plugin_mgr = new OVMS::Server::Plugin();

# Auto-flush
select STDERR; $|=1;
select STDOUT; $|=1;

########################################################
# Main event loop entry

EventCall('StartRun');

EV::loop();

########################################################
# Information timer

my %info_counts;
sub info_count
  {
  my ($topic,$count) = @_;

  if ($count > 0)
    { $info_counts{$topic} = $count; }
  else
    { delete $info_counts{$topic} }
  }

sub info_tim
  {
  # Log current informational counts

  my @counts;
  foreach my $topic (sort keys %info_counts)
    {
    push @counts,"$topic=".$info_counts{$topic};
    }

  return if (scalar @counts == 0);

  AE::log info => "- - - statistics: " . join(', ',@counts);
  }
