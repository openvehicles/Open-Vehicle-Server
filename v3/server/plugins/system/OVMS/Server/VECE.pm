#!/usr/bin/perl

########################################################################
# OVMS Server VECE plugin
#
# This plugin provides support for expansion of vehicle error codes
# into textual messages. It is used primarily by the push notification
# system to expand vehicle error alert notifications. It's configuration
# files are stored in 'vece/*.vece', usually with one file per vehicle
# type.

package OVMS::Server::VECE;

use strict;
use warnings;
use Carp;

use AnyEvent;
use AnyEvent::Log;
use Config::IniFiles;
use OVMS::Server::Plugin;

use Exporter qw(import);

our @EXPORT = qw();

# Vehicle Error Code Expansion configurations...

my $me; # Reference to our singleton object

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

  $self->{'config'} = Config::IniFiles->new();

  foreach (sort glob 'vece/*.vece')
    {
    my $vecef = $_;
    AE::log info => "- - - loading $vecef";
    my $vece = Config::IniFiles->new(-file => $vecef);
    foreach ($vece->Sections())
      {
      my $s = $_;
      $self->{'config'}->AddSection($s);
      foreach ($vece->Parameters($s))
        {
        my $p = $_;
        $self->{'config'}->newval($s,$p,$vece->val($s,$p));
        }
      }
    }
  }

sub expansion
  {
  my ($self,$vehicletype,$errorcode,$errordata) = @_;

  my $car = $vehicletype;
  while ($car ne '')
    {
    my $t = $self->{'config'}->val($car,$errorcode);
    if (defined $t)
      {
      my $text = sprintf $t,$errordata;
      return "Vehicle Alert #$errorcode: ".$text;
      }
    $car = substr($car,0,-1);
    }

  return sprintf "Vehicle Alert Code: %s/%d (%08x)",$vehicletype,$errorcode,$errordata;
  }

1;
