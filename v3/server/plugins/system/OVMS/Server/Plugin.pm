#!/usr/bin/perl

########################################################################
# OVMS Server Plugin Manager
#
# This plugin provides the OVMS plugin manager, and is always
# automatically loaded.

package OVMS::Server::Plugin;

use strict;
use warnings;
use Carp;

use AnyEvent;
use AnyEvent::Log;
use Config::IniFiles;
use OVMS::Server::Core;

use Exporter qw(import);

our @EXPORT = qw(PluginLoaded PluginCall
                 RegisterFunction FunctionRegistered FunctionCall
                 RegisterEvent EventRegistered EventCall);

my $me;           # Reference to our singleton object
my %plugins;      # Registered plugin modules
my %functions;    # Registered functions
my %events;       # Registered events

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

  return $self;
  }

sub init
  {
  my ($self) = @_;

  EventCall('PluginsLoading');

  my $pluginlist = MyConfig()->val('plugins','load',"DbDBI");
  foreach my $plug (split /\n/,$pluginlist)
    {
    my $obj;

    AE::log info => "- - - loading plugin $plug...";
    eval
      {
      eval join('','use OVMS::Server::',$plug,';');
      AE::log error => "- - - error in $plug: $@" if ($@);
      eval join('','$obj = new OVMS::Server::',$plug,';');
      AE::log error => "- - - error in $plug: $@" if ($@);
      $plugins{$plug} = $obj;
      };
    if (!defined $plugins{$plug})
      {
      AE::log error => "- - - plugin $plug could not be installed";
      }
    }

  EventCall('PluginsLoaded');
  }

sub PluginLoaded
  {
  my ($plugin) = @_;

  return defined $plugins{$plugin};
  }

sub PluginCall
  {
  my ($plugin, $function, @params) = @_;

  if (defined $plugins{$plugin})
    {
    return $plugins{$plugin}->$function(@params);
    }
  else
    {
    return undef;
    }
  }

sub RegisterFunction
  {
  my ($fn, $callback) = @_;

  my ($caller) = caller;
  ($caller) = caller(1) if ($caller eq 'OVMS::Server::Plugin');

  AE::log info => "- - -   RegisterFunction $fn for $caller";

  $functions{$fn} = $callback;
  }

sub FunctionRegistered
  {
  my ($fn) = @_;

  return defined $functions{$fn};
  }

sub FunctionCall
  {
  my ($fn, @params) = @_;

  if (defined $functions{$fn})
    {
    my $cb = $functions{$fn};
    return $cb->(@params);
    }
  else
    {
    AE::log error => "- - - Function $fn does not exist";
    return undef;
    }
  }

sub RegisterEvent
  {
  my ($event, $callback) = @_;

  my ($caller) = caller;
  ($caller) = caller(1) if ($caller eq 'OVMS::Server::Plugin');

  AE::log info => "- - -   RegisterEvent $event for $caller";

  $events{$event}{$caller} = $callback;
  }

sub EventRegistered
  {
  my ($event) = @_;

  return defined $events{$event};
  }

sub EventCall
  {
  my ($event, @params) = @_;

  my @results = ();
  if (defined $events{$event})
    {
    foreach my $caller (sort keys %{$events{$event}})
      {
      my $cb = $events{$event}{$caller};
      push @results, $cb->(@params);
      }
    }

  return @results;
  }

1;
