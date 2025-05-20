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
use AnyEvent::Util;
use Net::APNS::Simple;
use OVMS::Server::Core;
use OVMS::Server::Plugin;

use Exporter qw(import);

our @EXPORT = qw();

# Push Notifications: APNS notification module

my $me; # Reference to our singleton object
my @apns_queue_sandbox;
my @apns_queue_production;
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

  $apns_running=1;
  SANDPROD: foreach my $sandbox (1,0)
    {
    my $apns;
    my @queue;
    if ($sandbox)
      {
      next SANDPROD if (scalar @apns_queue_sandbox == 0);
      $apns = Net::APNS::Simple->new(
        development => 1,
        cert_file => 'conf/ovms_apns_sandbox.pem',
	key_file => 'conf/ovms_apns_sandbox.pem',
        passwd_cb => sub { return '' },
        bundle_id => 'com.openvehicles.ovms'
        );
      @queue = @apns_queue_sandbox;
      @apns_queue_sandbox = ();
      }
    else
      {
      next SANDPROD if (scalar @apns_queue_production == 0);
      $apns = Net::APNS::Simple->new(
        cert_file => 'conf/ovms_apns_production.pem',
        key_file => 'conf/ovms_apns_production.pem',
        passwd_cb => sub { return '' },
        bundle_id => 'com.openvehicles.ovms'
        );
      @queue = @apns_queue_production;
      @apns_queue_production = ();
      }

    AE::log info => "- - - msg apns processing ".(scalar @queue)." queued notification(s) for ".($sandbox?'sandbox':'production');
    fork_call
      {
      my %results = ();
      foreach my $rec (@queue)
        {
	my $vehicleid = $rec->{'vehicleid'};
        my $alerttype = $rec->{'alerttype'};
        my $alertmsg = $rec->{'alertmsg'};
	my $pushkeyvalue = $rec->{'pushkeyvalue'};
	my $appid = $rec->{'appid'};
        $apns->prepare(
	  $pushkeyvalue,
	  {
          aps => {
            alert => $vehicleid . "\n" . $alertmsg,
            badge => 0,
            sound => "default",
            },
          },
	  sub {
            my ($header, $content) = @_;
	    my %result = @{$header};
	    my $status = (defined $result{':status'})?$result{':status'}:'unknown';
	    my $reason = (defined $result{'reason'})?$result{'reason'}:'';
	    AE::log info => "- - $vehicleid msg apns message sent to $pushkeyvalue with $status:$reason";
            }
          );
        }
      $apns->notify();
      }
    sub
      {
      # process child result
      my $result = shift;
      $apns_running=0;
      AE::log info => "- - - msg apns completed ".(scalar @queue)." queued notification(s) for ".($sandbox?'sandbox':'production');
      }
    }
  }

1;
