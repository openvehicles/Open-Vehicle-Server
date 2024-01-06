#!/usr/bin/perl

########################################################################
# OVMS Server PUSH to GCM (FCM) notification plugin
#
# This plugin provides support for the GCM/FCM push notification system.
# It requires plugin 'Push' be loaded in order to function.
# 
# Configuration:
#   [gcm]
#   api_key_file=<path_to_api_key_file.json>
#   interval=10
# 
# See /v3/README on how to get an API key file.
# 


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
use JSON::XS;
use Try::Tiny;
use Digest::SHA qw(sha256 sha512);
use WWW::FCM::HTTP::V1;

use Exporter qw(import);

our @EXPORT = qw();

# Push Notifications: GCM notification module

my $me; # Reference to our singleton object
my @gcm_queue;
my $gcm_running;
my $gcm_api_key_file;
my $gcm_api_key_json;
my $gcm_project_id;
my $gcm_api_url;
my $gcm_con;
my $gcm_timer;

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

  # Init FCM connection:
  $gcm_api_key_file = MyConfig()->val('gcm','api_key_file');
  if (!defined $gcm_api_key_file)
    {
    AE::log warn => "- - - GCM API key file not configured => GCM disabled";
    }
  else
    {
    if (open my $fh, '<', $gcm_api_key_file)
      {
      $gcm_api_key_json = do { local $/; <$fh> };
      close $fh;
      }
    else
      {
      AE::log warn => "- - - GCM API key file $gcm_api_key_file not found => GCM disabled";
      }
    }
  if (defined $gcm_api_key_json)
    {
    try
      {
      my $api_key = decode_json($gcm_api_key_json);
      $gcm_project_id = $api_key->{'project_id'};
      }
    catch
      {
      AE::log warn => "- - - GCM API key file $gcm_api_key_file invalid => GCM disabled";
      };
    }
  if (defined $gcm_project_id)
    {
    $gcm_api_url = "https://fcm.googleapis.com/v1/projects/$gcm_project_id/messages:send";
    $gcm_con = WWW::FCM::HTTP::V1->new(
      {
      api_url      => $gcm_api_url,
      api_key_json => $gcm_api_key_json,
      });
    AE::log info => "- - - GCM initialized for project $gcm_project_id, API URL $gcm_api_url";
    }

  # Start ticker:
  my $gcm_interval = MyConfig()->val('gcm','interval',10);
  $gcm_timer = AnyEvent->timer (after => $gcm_interval, interval => $gcm_interval, cb => \&gcm_tim);

  return $self;
  }

sub init
  {
  my ($self) = @_;
  }

sub PushNotifyGCM
  {
  my ($rec) = @_;
  return if (!defined $gcm_con);

  push @gcm_queue,$rec;

  return;
  }

sub PushNow
  {
  &gcm_tim();
  }

sub gcm_tim
  {
  return if (!defined $gcm_con);
  return if (defined $gcm_running);
  return if (scalar @gcm_queue == 0);

  # WWW::FCM::HTTP::V1->send() is synchronous, needs ~0.3 seconds per call.
  # Fork child process for asynchronous push message delivery:
  my $pid = fork;
  if (!defined $pid)
    {
    AE::log error => "- - - msg gcm processing: fatal: cannot create child process";
    return;
    }

  if ($pid == 0)
    {
    # we're the child process
    AE::log info => "- - - msg gcm processing ".(scalar @gcm_queue)." queued notification(s)";

    foreach my $rec (@gcm_queue)
      {
      my $owner = $rec->{'owner'};
      my $vehicleid = $rec->{'vehicleid'};
      my $alerttype = $rec->{'alerttype'};
      my $alertmsg = $rec->{'alertmsg'};
      my $timestamp = $rec->{'timestamp'};
      my $pushkeyvalue = $rec->{'pushkeyvalue'};
      my $appid = $rec->{'appid'};
      AE::log info => "- - $vehicleid msg gcm '$alertmsg' => $pushkeyvalue";

      my $res = $gcm_con->send(
        {
        message =>
          {
          token          => $pushkeyvalue,
          data =>
            {
            type         => $alerttype,
            time         => $timestamp,
            title        => $vehicleid,
            message      => $alertmsg,
            },
          android =>
            {
            collapse_key => unpack("H*", sha256($alerttype . $timestamp . $vehicleid . $alertmsg)),
            },
          },
        });

      if ($res->is_success)
        {
        AE::log debug => "- - $vehicleid msg gcm message sent to $pushkeyvalue";
        }
      else
        {
        AE::log trace => "- - $vehicleid msg gcm failure response: " . $res->{'content'};
        my $rescont = decode_json($res->{'content'});
        my $errcode = $rescont->{'error'}{'code'};
        my $errmsg = $rescont->{'error'}{'message'};
        AE::log error => "- - $vehicleid msg gcm error $errcode on $pushkeyvalue: $errmsg";
        # App instance unregistered from FCM?
        # see https://firebase.google.com/docs/reference/fcm/rest/v1/ErrorCode
        if ($errcode == 404)
          {
          AE::log info => "- - $vehicleid msg gcm unregister $appid";
          FunctionCall('DbUnregisterPushNotify',$owner,$vehicleid,$appid);
          }
        }
      }
    # exit child process
    exit 0;
    }
  else
    {
    # we're the main process
    $gcm_running = AnyEvent->child (pid => $pid, cb => sub
      {
      AE::log info => "- - - msg gcm processing finished";
      undef $gcm_running;
      }
    );
    @gcm_queue = ();
    }
  }

1;
