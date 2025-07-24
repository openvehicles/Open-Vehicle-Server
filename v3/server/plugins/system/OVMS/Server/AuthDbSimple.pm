#!/usr/bin/perl

########################################################################
# Authentication via Demo
#
# This plugin provides for authentication using simple unencrypted
# plain text passwords in the database.
# It should only be used in private, never public, environments.

package OVMS::Server::AuthDbSimple;

use strict;
use warnings;
use Carp;

use AnyEvent;
use AnyEvent::Log;
use Digest::SHA qw(sha256 sha512);
use OVMS::Server::Core;
use OVMS::Server::Plugin;

use Exporter qw(import);

our @EXPORT = qw();

# Authentication: DbSimple

use vars qw{
  $config
  };

sub new
  {
  my $class = shift;
  $class = ref($class) || $class;
  my $self = {@_};
  bless( $self, $class );

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

  my $rec = FunctionCall('DbGetOwner',$user);
  return '' if (!defined $rec); # Authentication fail if user record not found

  # Check user password authentication
  my $dbpass = $rec->{'pass'};
  return '' if (!defined $dbpass); # Authentication fails if no password

  if ($password eq $dbpass)
    {
    # Full permissions for a user+pass authentication
    AE::log debug => '- - - Authentication via username+password';
    return '*';
    }

  # Otherwise, authentication failed
  return '';
  }

1;
