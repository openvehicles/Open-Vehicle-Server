#!/usr/bin/perl

########################################################################
# OVMS Server PUSH to EXPO notification plugin
#
# This plugin provides support for push notifications via EXPO.
# It requires plugin 'Push' be loaded in order to function.

package OVMS::Server::PushEXPO;

use strict;
use warnings;
use Carp;

use AnyEvent;
use AnyEvent::Log;
use AnyEvent::HTTP;
use OVMS::Server::Core;
use OVMS::Server::Plugin;
use JSON::XS;

use Exporter qw(import);

our @EXPORT = qw();

# Push Notifications: EXPO notifications

my $me; # Reference to our singleton object
my @expo_queue;
my %expo_done;
my $expo_running=0;
my $expo_ticker;

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

  RegisterFunction('PushNotify:expo',\&PushNotifyEXPO);
  RegisterEvent('PushNow',\&PushNow);

  $expo_ticker = AnyEvent->timer (after => 10, interval => 10, cb => \&expo_tim);

  return $self;
  }

sub init
  {
  my ($self) = @_;
  }

sub PushNotifyEXPO
  {
  my ($rec) = @_;

  push @expo_queue,$rec;
  return;
  }

sub PushNow
  {
  &expo_tim() if (!$expo_running);
  }

sub expo_check
  {
  my $now = time;

  AE::log info => "- - - expo checking with done size ". (scalar keys %expo_done);

  my @batch = ();
  foreach my $id (keys %expo_done)
    {
    my $rec = $expo_done{$id};
    my $token = $rec->{'to'};
    my $sent = $rec->{'data'}->{'sent'};
    if (($now - $sent) > (30*60))
      {
      # More than 30 minutes have passed, so we just remove the record
      delete $expo_done{$id};
      }
    elsif (($now - $sent) > 10)
      {
      # Enough time has passed that we can check the record
      push @batch, $id if (scalar @batch < 90);
      }
    }

  if (scalar @batch > 0)
    {
    AE::log info => "- - - expo checking batch of ". (scalar @batch);
    $expo_running=1;
    my %request = ( 'ids' => \@batch );
    my $json = JSON::XS->new->utf8->canonical->encode(\%request);
    my %headers = (
      'Content-Type' => 'application/json',
      'accept' => 'application/json',
      'accept-encoding' => 'gzip, deflate' );
    http_post 'https://exp.host/--/api/v2/push/getReceipts',
      $json,
      headers => \%headers,
      sub {
      my ($data, $headers) = @_;
      eval
        {
        my $json = JSON::XS->new->utf8->canonical->decode($data);
        if (defined $json->{'data'})
          {
          my $results = $json->{'data'};
          foreach my $id (keys %{$results})
            {
            my $status = $results->{$id}->{'status'};
	    my $msg = $results->{$id}->{'message'};
            my $vehicleid = $expo_done{$id}->{'data'}->{'vehicleid'};
            my $token = $expo_done{$id}->{'to'};
            if ($status eq 'ok')
              {
              AE::log info => "- - $vehicleid msg expo check ok $token";
              delete $expo_done{$id};
              }
            else
              {
              AE::log error => "- - $vehicleid msg expo check failed $token with $status $msg";
              }
            }
          }
        };
      if ($@)
        {
        AE::log error => "- - - msg expo failed batch checking $@";
        }
      $expo_running=0;
      }
    }
  }

sub expo_tim
  {
  return if ($expo_running);

  my $qs = scalar @expo_queue;
  my $ds = scalar keys %expo_done;

  if ($qs == 0)
    {
    &expo_check() if ($ds > 0);
    return;
    }

  AE::log info => "- - - expo push running=$expo_running and queue=$qs and done=$ds";
  $expo_running=1;

  my @batch = ();
  while ((scalar @expo_queue > 0) && (scalar @batch < 90))
    {
    my $rec = shift @expo_queue;
    my $owner = $rec->{'owner'};
    my $vehicleid = $rec->{'vehicleid'};
    my $alerttype = $rec->{'alerttype'};
    my $alertmsg = $rec->{'alertmsg'};
    my $pushkeyvalue = $rec->{'pushkeyvalue'};

    my $notify = {
      'to' => $pushkeyvalue,
      'title' => 'Open Vehicles ' . $vehicleid,
      'body' => $alertmsg,
      'sound' => 'default',
      'badge' => 0,
      'data' => { 'vehicleid' => $vehicleid, 'alerttype' => $alerttype, 'sent' => time }
      };
    push @batch,$notify;
    }

  if (scalar @batch > 0)
    {
    AE::log info => "- - - expo sending batch of ". (scalar @batch);
    my $json = JSON::XS->new->utf8->canonical->encode(\@batch);
    my %headers = (
      'Content-Type' => 'application/json',
      'accept' => 'application/json',
      'accept-encoding' => 'gzip, deflate' );
    http_post 'https://exp.host/--/api/v2/push/send',
      $json,
      headers => \%headers,
      sub
        {
        my ($data, $headers) = @_;
        AE::log info => "- - - expo received response";
        my $json = JSON::XS->new->utf8->canonical->decode($data);
        eval
          {
          my $result = JSON::XS->new->utf8->canonical->decode($data);
          if (defined $result->{'data'})
            {
            my $idx = 0;
            foreach my $rrec (@{$result->{'data'}})
              {
              my $status = $rrec->{'status'};
              my $id = $rrec->{'id'};
              if ($status eq 'ok')
                {
                $expo_done{$id} = $batch[$idx];
                my $vehicleid = $batch[$idx]->{'data'}->{'vehicleid'};
                AE::log info => "- - $vehicleid msg expo sent successfully";
                }
              else
                {
                my $vehicleid = $batch[$idx]->{'data'}->{'vehicleid'};
                my $to = $batch[$idx]->{'to'};
		my $msg = $rrec->{'message'};
                AE::log error => "- - $vehicleid msg expo failed $to with $status $msg";
                }
              $idx++;
              }
            }
          };
        if ($@)
          {
          AE::log error => "- - - msg expo failed batch processing $@";
          }
        $expo_running=0;
        };
    AE::log info => "- - - expo batch dispatched";
    }
  }

1;
