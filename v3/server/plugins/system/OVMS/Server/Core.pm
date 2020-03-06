#!/usr/bin/perl

########################################################################
# OVMS Server Core
#
# This plugin provides the core of the OVMS system, and is always
# automatically loaded.

package OVMS::Server::Core;

use strict;
use warnings;
use Carp;

use AnyEvent;
use AnyEvent::Log;
use Config::IniFiles;
use POSIX qw(strftime);

use Exporter qw(import);

our @EXPORT = qw(MyConfig IsPermitted UTCDate UTCDateFull UTCTime GetVersion);

my $VERSION;
if (-e '/usr/bin/git')
  { $VERSION = `/usr/bin/git describe --always --tags --dirty`; }
else
  { $VERSION = '3.0.0-custom'; }

my $me;                         # Reference to our singleton object

use vars qw{
  $config
  };

sub new
  {
  my $class = shift;
  $class = ref($class) || $class;
  my $self = {@_};
  bless( $self, $class );

  $me = $self;
  $self->init();

  return $self;
  }

sub init
  {
  my ($self) = @_;

  $self->{'config'} = Config::IniFiles->new(-file => 'conf/ovms_server.conf');
  }

sub GetVersion
  {
  return $VERSION;
  }

sub MyConfig
  {
  return $me->{'config'};
  }

sub IsPermitted
  {
  my ($permissions, @rights) = @_;

  return 1 if ($permissions eq '*');

  my %ph = map { lc($_) => 1 } split(/\s*,\s*/,$permissions);

  foreach my $right (@rights)
    {
    return 1 if (defined $ph{lc($right)});
    }

  return 0;
  }

sub UTCDate
  {
  my ($t) = @_;
  $t = time if (!defined $t);

  return strftime "%Y-%m-%d", gmtime($t);
  }

sub UTCDateFull
  {
  my ($t) = @_;
  $t = time if (!defined $t);

  return strftime "%Y-%m-%d 00:00:00", gmtime($t);
  }

sub UTCTime
  {
  my ($t) = @_;
  $t = time if (!defined $t);

  return strftime "%Y-%m-%d %H:%M:%S", gmtime($t);
  }

1;
