#!/usr/bin/perl

########################################################################
# OVMS Server PUSH to GCM notification plugin
#
# This plugin provides support for the GCM push notification system.
# It requires plugin 'Push' be loaded in order to function.

package OVMS::Server::PushGCM;

use strict;
use warnings;
use Carp;

use AnyEvent;
use AnyEvent::Log;
use AnyEvent::HTTP;
use URI::Escape;
use OVMS::Server::Core;
use OVMS::Server::Plugin;

use Exporter qw(import);

our @EXPORT = qw();

# Push Notifications: GCM notification module

my $me; # Reference to our singleton object
my @gcm_queue;
my $gcm_running=0;
my $gcm_interval;

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

  RegisterFunction('PushNotify:gcm',\&PushNotifyGCM);
  RegisterEvent('PushNow',\&PushNow);

  $gcm_interval = MyConfig()->val('gcm','interval',10);
  my $gcmtim = AnyEvent->timer (after => $gcm_interval, interval => $gcm_interval, cb => \&gcm_tim);

  return $self;
  }

sub init
  {
  my ($self) = @_;
  }

sub PushNotifyGCM
  {
  my ($rec) = @_;

  push @gcm_queue,$rec;

  &gcm_tim();

  return;
  }

sub PushNow
  {
  &gcm_tim() if ($gcm_running==0);
  }

sub gcm_tim
  {
  return if ($gcm_running>0);
  return if (scalar @gcm_queue == 0);

  my $apikey = MyConfig()->val('gcm','apikey');
  return if ((!defined $apikey)||($apikey eq ''));

  AE::log info => "- - - msg gcm processing ".(scalar @gcm_queue)." queued notification(s)";

  foreach my $rec (@gcm_queue)
    {
    $gcm_running++;
    my $vehicleid = $rec->{'vehicleid'};
    my $alerttype = $rec->{'alerttype'};
    my $alertmsg = $rec->{'alertmsg'};
    my $timestamp = $rec->{'timestamp'};
    my $pushkeyvalue = $rec->{'pushkeyvalue'};
    my $appid = $rec->{'appid'};
    AE::log info => "- - $vehicleid msg gcm '$alertmsg' => $pushkeyvalue";
    my $body = 'registration_id='.uri_escape($pushkeyvalue)
              .'&data.title='.uri_escape($vehicleid)
              .'&data.type='.uri_escape($alerttype)
              .'&data.message='.uri_escape($alertmsg)
              .'&data.time='.uri_escape($timestamp)
              .'&collapse_key='.time;
    http_request
      POST=>'https://fcm.googleapis.com/fcm/send',
      body => $body,
      headers=>{ 'Authorization' => 'key='.$apikey,
                 "Content-Type" => "application/x-www-form-urlencoded" },
      sub
        {
        my ($data, $headers) = @_;
        $gcm_running--;
        foreach (split /\n/,$data)
          { AE::log info => "- - - msg gcm message sent ($_)"; }
        };
    }
  @gcm_queue = ();
  AE::log info => "- - - msg gcm has been launched";
  }

1;
