#!/usr/bin/perl

########################################################################
# Authentication via Configuration file
#
# This plugin provides for authentication via configuration file.
# Note: Only one Auth* plugin should be loaded at any one time.
#
# This is a work-in-progress and has not been completed yet.

package OVMS::Server::AuthConfig;

use strict;
use warnings;
use Carp;

use AnyEvent;
use AnyEvent::Log;
use Config::IniFiles;
use OVMS::Server::Core;
use OVMS::Server::Plugin;

use Exporter qw(import);

our @EXPORT = qw();

# Authentication: Config (authenticate against manual entries in the configuration)

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

  $config = MyConfig;

  RegisterFunction('Authenticate',\&Authenticate);

  return $self;
  }

sub init
  {
  my ($self) = @_;
  }

sub Authenticate
  {
  my ($user,$password) = @_;

  if ($config->exists('plugin_auth',$user))
    {
    return '*' if ($config->val('plugin_auth',$user) eq $password);
    }

  return ''; # Authentication default
  }

1;
