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
