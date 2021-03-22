#!/usr/bin/perl

########################################################################
# OVMS Server PUSH to APNS notification plugin
#
# This plugin provides support for the APNS push notification system.
# It requires plugin 'Push' be loaded in order to function.

package OVMS::Server::PushAPNS;

use strict;
use warnings;
use Carp;

use EV;
use AnyEvent;
use AnyEvent::Log;
use AnyEvent::IO;
use AnyEvent::Socket;
use AnyEvent::Handle;
use OVMS::Server::Core;
use OVMS::Server::Plugin;

use Exporter qw(import);

our @EXPORT = qw();

# Push Notifications: APNS notification module

my $me; # Reference to our singleton object
my @apns_queue_sandbox;
my @apns_queue_production;
my @apns_queue;
my $apns_handle;
my $apns_running=0;
my $apns_interval;
my $apnstim;

if (!PluginLoaded('Push'))
  {
  AE::log error => "Error: Push MUST be loaded before this plugin";
  }

use vars qw{
  };

sub new
  {
  my $class = shift;
  $class = ref($class) || $class;
  my $self = {@_};
  bless( $self, $class );

  $me = $self;
  $self->init();

  RegisterFunction('PushNotify:apns',\&PushNotifyAPNS);
  RegisterEvent('PushNow',\&PushNow);

  $apns_interval = MyConfig()->val('apns','interval',10);
  $apnstim = AnyEvent->timer (after => $apns_interval, interval => $apns_interval, cb => \&apns_tim);

  return $self;
  }

sub init
  {
  my ($self) = @_;
  }

sub PushNotifyAPNS
  {
  my ($rec) = @_;

  if ($rec->{'pushkeyvalue'} eq '{length=32')
    {
    AE::log error => join(' ',
                          '- -',
                          $rec->{'owner'}.'/'.$rec->{'vehicleid'},
                          'msg skipped apns notification for',
                          $rec->{'pushkeytype'}.':'.$rec->{'appid'},
                          '- invalid token');
    return;
    }

  if ($rec->{'pushkeytype'} eq 'sandbox')
    { push @apns_queue_sandbox,$rec; }
  else
    { push @apns_queue_production,$rec; }

  return;
  }

sub PushNow
  {
  &apns_tim() if (!$apns_running);
  }

sub apns_tim
  {
  return if ($apns_running);
  return if ((scalar @apns_queue_sandbox == 0)&&(scalar @apns_queue_production == 0));

  my ($host,$certfile,$keyfile);
  if (scalar @apns_queue_sandbox > 0)
    {
    # We have notifications to deliver for the sandbox
    @apns_queue = @apns_queue_sandbox;
    @apns_queue_sandbox = ();
    $host = 'gateway.sandbox.push.apple.com';
    $certfile = $keyfile = 'conf/ovms_apns_sandbox.pem';
    }
  elsif (scalar @apns_queue_production > 0)
    {
    @apns_queue = @apns_queue_production;
    @apns_queue_production = ();
    $host = 'gateway.push.apple.com';
    $certfile = $keyfile = 'conf/ovms_apns_production.pem';
    }

  AE::log info => "- - - msg apns processing ".(scalar @apns_queue)." queued notification(s) for $host";
  $apns_running=1;

  tcp_connect $host, 2195, sub
    {
    my ($fh) = @_;

    if (!defined $fh)
      {
      AE::log error => "- - - msg apns processing ERROR connecting $host: $!";
      $apns_running = 0;
      }
    else
      {
      AE::log info => "- - - msg apns connected to $host, now establishing SSL security";
      $apns_handle = new AnyEvent::Handle(
          fh       => $fh,
          peername => $host,
          tls      => "connect",
          tls_ctx  => { cert_file => $certfile, key_file => $keyfile, verify => 0, verify_peername => $host },
          on_error => sub
                {
                my ($hdl, $fatal, $msg) = @_;
                AE::log error => "- - - msg apns processing ABORT for $host: $msg";
                $apns_handle = undef;
                $apns_running = 0;
                $_[0]->destroy;
                },
          timeout    => 60,
          on_timeout => sub
                {
                AE::log error => "- - - msg apns processing ABORT for $host: TIMEOUT";
                $apns_handle = undef;
                $apns_running = 0;
                $_[0]->destroy;
                },
          on_starttls => \&apns_push,
          on_stoptls  => sub
                {
                AE::log error => "- - - msg apns processing ABORT for $host: connection closed";
                $apns_handle = undef;
                $apns_running = 0;
                $_[0]->destroy;
                }
          );
      }
    };
  AE::log info => "- - - msg apns has been launched";
  }

sub apns_push
  {
  my ($hdl, $success, $error_message) = @_;

  if (!$success)
    {
    AE::log error => "- - - connection to apns FAILED: $error_message";
    undef $apns_handle;
    $apns_running=0;
    return;
    }

  my $fn = $hdl->fh->fileno();
  AE::log info => "#$fn - - connected to apns for push notification";

  foreach my $rec (@apns_queue)
    {
    my $vehicleid = $rec->{'vehicleid'};
    my $alerttype = $rec->{'alerttype'};
    my $alertmsg = $rec->{'alertmsg'};
    my $pushkeyvalue = $rec->{'pushkeyvalue'};
    my $appid = $rec->{'appid'};
    AE::log info => "#$fn - $vehicleid msg apns '$alertmsg' => $pushkeyvalue";
    &apns_send( $pushkeyvalue => { aps => { alert => "$vehicleid\n$alertmsg", sound => 'default' } } );
    }
  $apns_handle->on_drain(sub
                {
                my ($hdl) = @_;
                my $fn = $hdl->fh->fileno();
                AE::log info => "#$fn - - msg apns is drained and done";
                undef $apns_handle;
                $apns_running=0;
                });
  }

sub apns_send
  {
  my ($token, $payload) = @_;

  my $json = JSON::XS->new->utf8->encode ($payload);

  my $btoken = pack "H*",$token;

  $apns_handle->push_write( pack('C', 0) ); # command

  $apns_handle->push_write( pack('n', bytes::length($btoken)) ); # token length
  $apns_handle->push_write( $btoken );                           # device token

  # Apple Push Notification Service refuses string values as badge number
  if ($payload->{aps}{badge} && looks_like_number($payload->{aps}{badge}))
    {
    $payload->{aps}{badge} += 0;
    }

  # The maximum size allowed for a notification payload is 256 bytes;
  # Apple Push Notification Service refuses any notification that exceeds this limit.
  if ( (my $exceeded = bytes::length($json) - 256) > 0 )
    {
    if (ref $payload->{aps}{alert} eq 'HASH')
      {
      $payload->{aps}{alert}{body} = &_trim_utf8($payload->{aps}{alert}{body}, $exceeded);
      }
    else
      {
      $payload->{aps}{alert} = &_trim_utf8($payload->{aps}{alert}, $exceeded);
      }

    $json = JSON::XS->new->utf8->encode($payload);
    }

  $apns_handle->push_write( pack('n', bytes::length($json)) ); # payload length
  $apns_handle->push_write( $json );                           # payload
  }

sub _trim_utf8
  {
  my ($string, $trim_length) = @_;

  my $string_bytes = JSON::XS->new->utf8->encode($string);
  my $trimmed = '';

  my $start_length = bytes::length($string_bytes) - $trim_length;
  return $trimmed if $start_length <= 0;

  for my $len ( reverse $start_length - 6 .. $start_length )
    {
    local $@;
    eval
      {
      $trimmed = JSON::XS->new->utf8->decode(substr($string_bytes, 0, $len));
      };
    last if $trimmed;
    }

  return $trimmed;
  }

1;
