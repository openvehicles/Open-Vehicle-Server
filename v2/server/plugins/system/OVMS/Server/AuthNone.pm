#!/usr/bin/perl

########################################################################
# Authentication Stub
#
# This plugin provides a stub implementation for authentication
# providers. It does nothing and will always deny authentication attempts.
# Note: Only one Auth* plugin should be loaded at any one time.

package OVMS::Server::AuthNone;

use strict;
use warnings;
use Carp;

use AnyEvent;
use AnyEvent::Log;
use OVMS::Server::Plugin;

use Exporter qw(import);

our @EXPORT = qw();

# Authentication: None (stub, everything fails)

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

  return ''; # Authentication always fails
  }

1;
