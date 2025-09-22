#!/usr/bin/perl

########################################################################
# OVMS Server PUSH notification plugin
#
# This plugin provides base support for Push Notification plugins.
# It exposes an interface to send a push notification, and dispatches
# those notifications to the appropriate handlers.

package OVMS::Server::Push;

use strict;
use warnings;
use Carp;

use AnyEvent;
use AnyEvent::Log;
use OVMS::Server::Core;
use OVMS::Server::Plugin;

use Exporter qw(import);

our @EXPORT = qw();

# Push Notifications: Core notification module

my $me;                         # Reference to our singleton object
my $notifyhistory_tim;          # Retain history push notifications (seconds)

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

  RegisterFunction('PushNotify',\&PushNotify);

  $notifyhistory_tim = MyConfig()->val('push','history',0);

  return $self;
  }

sub init
  {
  my ($self) = @_;
  }

my $notifyhistory_rec = 0;
sub PushNotify
  {
  my ($owner, $vehicleid, $alerttype, $alertmsg) = @_;

  my $vkey = $owner . '/' . $vehicleid;
  my $timestamp = UTCTime();

  # VECE expansion...
  if ($alerttype eq 'E')
    {
    my ($vehicletype,$errorcode,$errordata) = split(/,/,$alertmsg);
    if (PluginLoaded('VECE'))
      {
      # VECE plugin is available
      $alertmsg = PluginCall('VECE','expansion',$vehicletype,$errorcode,$errordata);
      }
    else
      {
      $alertmsg = sprintf "Vehicle Alert Code: %s/%d (%08x)",$vehicletype,$errorcode,$errordata;
      }
    }

  # Log the alert
  if ($notifyhistory_tim > 0)
    {
    FunctionCall('DbSaveHistorical',UTCTime(),"*-Log-Notification",$notifyhistory_rec++,$owner,$vehicleid,"$alerttype,$alertmsg",UTCTime(time+$notifyhistory_tim));
    $notifyhistory_rec=0 if ($notifyhistory_rec>65535);
    }

  # Ignore DMC (debug) alerts
  return if (($alerttype eq 'E') && ($alertmsg =~ /\:\sDMC\:/));

  # Push the notifications out to subscribers...
  CANDIDATE: foreach my $row (FunctionCall('DbGetNotify',$owner,$vehicleid))
    {
    my %rec;
    $rec{'owner'} = $owner;
    $rec{'vehicleid'} = $vehicleid;
    $rec{'alerttype'} = $alerttype;
    $rec{'alertmsg'} = $alertmsg;
    $rec{'timestamp'} = $timestamp;
    $rec{'pushkeytype'} = $row->{'pushkeytype'};
    $rec{'pushkeyvalue'} = $row->{'pushkeyvalue'};
    $rec{'appid'} = $row->{'appid'};

    my $pushcall = 'PushNotify:' . $row->{'pushtype'};
    if (FunctionRegistered($pushcall))
      {
      AE::log info => "- - $vkey msg queued $row->{'pushtype'} notification for $rec{'pushkeytype'}:$rec{'appid'}";
      FunctionCall('PushNotify:'.$row->{'pushtype'}, \%rec);
      }
    else
      {
      AE::log info => "- - $vkey msg no notification handler registered for ".$rec{'pushkeytype'};
      }
    }
  EventCall('PushNow');

  return;
  }

1;
