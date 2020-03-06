#!/usr/bin/perl

########################################################################
# OVMS Server PUSH to MAIL notificaiton plugin
#
# This plugin provides support for push notifications via EMAIL.
# It requires plugin 'Push' be loaded in order to function.

package OVMS::Server::PushMAIL;

use strict;
use warnings;
use Carp;

use AnyEvent;
use AnyEvent::Log;
use OVMS::Server::Core;
use OVMS::Server::Plugin;
use Email::MIME;
use Email::Sender::Simple qw(sendmail);

use Exporter qw(import);

our @EXPORT = qw();

# Push Notifications: MAIL notification module

my $me; # Reference to our singleton object
my @mail_queue;
my $mail_sender;
my $mail_interval;
my $mail_running=0;
my $mailtim;

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

  RegisterFunction('PushNotify:mail',\&PushNotifyMAIL);
  RegisterEvent('PushNow',\&PushNow);

  $mail_sender = MyConfig()->val('mail','sender','notifications@openvehicles.com');
  $mail_interval = MyConfig()->val('mail','interval',10);
  $mailtim = AnyEvent->timer (after => $mail_interval, interval => $mail_interval, cb => \&mail_tim);

  return $self;
  }

sub init
  {
  my ($self) = @_;
  }

sub PushNotifyMAIL
  {
  my ($rec) = @_;

  push @mail_queue,$rec;

  return;
  }

sub PushNow
  {
  &mail_tim() if (!$mail_running);
  }

sub mail_tim
  {
  return if ($mail_running);
  return if (scalar @mail_queue == 0);

  $mail_running=1;
  my @queue = @mail_queue;
  @mail_queue = ();

  foreach my $rec (@queue)
    {
    my $owner = $rec->{'owner'};
    my $vehicleid = $rec->{'vehicleid'};
    my $alerttype = $rec->{'alerttype'};
    my $alertmsg = $rec->{'alertmsg'};
    my $pushkeyvalue = $rec->{'pushkeyvalue'};
    if ($pushkeyvalue =~ /@/)
      {
      AE::log info => "- - $vehicleid msg mail '$alertmsg' => '$pushkeyvalue'";
      my $message = Email::MIME->create(
        header_str => [
          From    => $mail_sender,
          To      => $pushkeyvalue,
          Subject => "OVMS notification type $alerttype from $vehicleid",
        ],
        attributes => {
          encoding => 'quoted-printable',
          charset  => 'ISO-8859-1',
        },
        body_str => $alertmsg,
      );
      sendmail($message);
      }
    }
  $mail_running=0;
  }

1;
