#!/usr/bin/perl

########################################################################
# Authentication via Drupal
#
# This plugin provides for authentication via Drupal database.
# Note: Only one Auth* plugin should be loaded at any one time.

package OVMS::Server::AuthDrupal;

use strict;
use warnings;
use Carp;

use AnyEvent;
use AnyEvent::Log;
use Digest::SHA qw(sha256 sha512);
use OVMS::Server::Plugin;

use Exporter qw(import);

our @EXPORT = qw();

# Authentication: Drupal (authenticate against drupal)

my $itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
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

  my $rec = FunctionCall('dbGetOwner',$user);
  return '' if (!defined $rec); # Authentication fail if user record not found

  # Check user password authentication
  my $dbpass = $rec->{'pass'};
  return '' if (!defined $dbpass); # Authentication fails if no password

  my $iter_log2 = index($itoa64,substr($dbpass,3,1));
  my $iter_count = 1 << $iter_log2;

  my $phash = substr($dbpass,0,12);
  my $salt = substr($dbpass,4,8);

  my $hash = sha512($salt.$password);
  do
    {
    $hash = sha512($hash.$password);
    $iter_count--;
    } while ($iter_count > 0);

  my $encoded = substr($phash . &drupal_password_base64_encode($hash,length($hash)),0,55);

  if ($encoded eq $dbpass)
    {
    # Full permissions for a user+pass authentication
    AE::log debug => 'Authentication via drupal username+password';
    return '*';
    }

  # Check api token authentication
  $rec = FunctionCall('DbGetToken',$user,$password);
  if (defined $rec)
    {
    AE::log debug => 'Authentication via drupal username+apitoken';
    return $rec->{'permit'};
    }

  # Otherwise, authentication failed
  return '';
  }

sub drupal_password_base64_encode
  {
  my ($input, $count) = @_;
  my $output = '';
  my $i = 0;
  do
    {
    my $value = ord(substr($input,$i++,1));
    $output .= substr($itoa64,$value & 0x3f,1);
    if ($i < $count)
      {
      $value |= ord(substr($input,$i,1)) << 8;
      $output .= substr($itoa64,($value >> 6) & 0x3f,1);
      }

    $i++;
    if ($i < $count)
      {
      $value |= ord(substr($input,$i,1)) << 16;
      $output .= substr($itoa64,($value >> 12) & 0x3f,1);
      }

    $i++;
    if ($i < $count)
      {
      $output .= substr($itoa64,($value >> 18) & 0x3f,1);
      }
    } while ($i < $count);

  return $output;
  }

1;
