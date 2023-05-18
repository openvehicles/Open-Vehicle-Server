#!/usr/bin/perl

########################################################################
# OVMS Server HTTP API plugin
#
# This plugin provides base support for a HTTP API server listening
# on ports tcp/6868 (plain HTTP) and tcp/6869 (SSL/TLS HTTPS). It is
# a base requirement of the other ApiHttp* plugins that provide the
# actual API methods.

package OVMS::Server::ApiHttp;

use strict;
use warnings;
use Carp;

use AnyEvent;
use AnyEvent::Log;
use AnyEvent::HTTPD;

use OVMS::Server::Core;
use OVMS::Server::Plugin;

use Exporter qw(import);

our @EXPORT = qw();

# API: HTTP

my $me;                       # Reference to our singleton object
my $httpapi_conns_count = 0;  # Count of the number of HTTP API connections
my $http_server;              # HTTP Server handle
my $https_server;             # HTTPS Server handle
my %registrations = ();       # URL registrations
my $request_ticker_w;         # A period request ticker

use vars qw{
  };

sub new
  {
  my $class = shift;
  $class = ref($class) || $class;
  my $self = {@_};
  bless( $self, $class );

  $me = $self;

  register_callback('', \&http_request_in_root);

  RegisterFunction('HttpServerRegisterCallback', \&register_callback);
  RegisterEvent('StartRun', \&start);

  return $self;
  }

sub start
  {
  AE::log info => "- - - starting HTTP server listener on port tcp/6868";
  $http_server = AnyEvent::HTTPD->new (port => 6868, request_timeout => 30, allowed_methods => ['GET','PUT','POST','DELETE']);
  $http_server->reg_cb ( %registrations );

  $http_server->reg_cb (
                  client_connected => sub {
                    my ($httpd, $host, $port) = @_;
                      $httpapi_conns_count++;
                      FunctionCall('InfoCount', 'HTTPAPI_conns', $httpapi_conns_count);
                      AE::log info => join(' ','http','-','-',$host.':'.$port,'connect');
                    }
                  );

  $http_server->reg_cb (
                  client_disconnected => sub {
                    my ($httpd, $host, $port) = @_;
                      $httpapi_conns_count--;
                      FunctionCall('InfoCount', 'HTTPAPI_conns', $httpapi_conns_count);
                      AE::log info => join(' ','http','-','-',$host.':'.$port,'disconnect');
                    }
                  );

  $http_server->reg_cb (request => \&request);

  my $pemfile = MyConfig()->val('httpapi','sslcrt','conf/ovms_server.pem');
  if (-e $pemfile)
    {
    AE::log info => "- - - starting HTTPS server listener on port tcp/6869";
    $https_server = AnyEvent::HTTPD->new (port => 6869, request_timeout => 30, ssl  => { cert_file => $pemfile }, allowed_methods => ['GET','PUT','POST','DELETE']);
    $https_server->reg_cb ( %registrations );

    $https_server->reg_cb (
                     client_connected => sub {
                       my ($httpd, $host, $port) = @_;
                         $httpapi_conns_count++;
                         FunctionCall('InfoCount', 'HTTPAPI_conns', $httpapi_conns_count);
                         AE::log info => join(' ','http','-','-',$host.':'.$port,'connect(ssl)');
                        }
                     );

    $https_server->reg_cb (
                     client_disconnected => sub {
                       my ($httpd, $host, $port) = @_;
                         $httpapi_conns_count--;
                         FunctionCall('InfoCount', 'HTTPAPI_conns', $httpapi_conns_count);
                         AE::log info => join(' ','http','-','-',$host.':'.$port,'disconnect(ssl)');
                       }
                    );

    $https_server->reg_cb (request => \&request);
    }
  $request_ticker_w = AnyEvent->timer (after => 60, interval => 60, cb => \&request_ticker);
  }

########################################################
# API HTTP request handler
#
# Attempts to rate-limit requests to ensure fair
# delivery of services

my %ratelimit;
sub request
  {
  my ($httpd, $req) = @_;
  my $host = $req->client_host;
  my $port = $req->client_port;
  my $key = $host . ':' . $port;

  my $burst = MyConfig()->val('httpapi','ratelimit_http_burst','120');
  my $delay = MyConfig()->val('httpapi','ratelimit_http_delay','20');
  my $expire = MyConfig()->val('httpapi','ratelimit_http_expire','300');

  if (!defined $ratelimit{$host})
    {
    # Initial allocation
    $ratelimit{$host}{'quota'} = $burst;
    }
  else
    {
     $ratelimit{$host}{'quota'}--;
     $ratelimit{$host}{'quota'}=0 if ($ratelimit{$host}{'quota'}<0);
    }
  AE::log info => join(' ','http','-','-',$host.':'.$port,'quota',$ratelimit{$host}{'quota'});
  $ratelimit{$host}{'expire'} = time + $expire;

  if ($ratelimit{$host}{'quota'} <= 0)
    {
    # Need to reject the call
    $httpd->stop_request;
    $ratelimit{$host}{'timers'}{$port} = AnyEvent->timer (after => $delay, cb => sub
      {
      delete $ratelimit{$host}{'timers'}{$port} if (defined $ratelimit{$host});
      my $url = $req->url;
      $url = $1 if ($url =~ /^(.+)\?.*$/);
      AE::log info => join(' ','http','-','-',$host.':'.$port,'too many requests (delayed)',$req->method,$url);
      $req->respond([429, "Too many requests"]);
      });
    }
  }

sub request_ticker
  {
  my $now = time;

  my $permin = MyConfig()->val('httpapi','ratelimit_http_permin','60');
  my $max = MyConfig()->val('httpapi','ratelimit_http_max','240');

  foreach my $host (keys %ratelimit)
    {
    if ($ratelimit{$host}{'expire'} <= $now)
      {
      delete $ratelimit{$host};
      }
    else
      {
      $ratelimit{$host}{'quota'} += $permin;
      $ratelimit{$host}{'quota'} = $max if ($ratelimit{$host}{'quota'} > $max);
      }
    }
  }

########################################################
# API HTTP server
#

sub register_callback
  {
  my ($url, $cb) = @_;

  my ($caller) = caller;
  ($caller) = caller(1) if ($caller eq 'OVMS::Server::Plugin');

  AE::log info => "- - - register callback url '$url' for $caller";

  $registrations{$url} = $cb;
  }

sub http_request_in_root
  {
  my ($httpd, $req) = @_;

  AE::log info => join(' ','http','-','-',$req->client_host.':'.$req->client_port,'-',$req->method,$req->url);

  $req->respond ( [404, 'not found', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "not found\n"] );
  $httpd->stop_request;
  }

1;
