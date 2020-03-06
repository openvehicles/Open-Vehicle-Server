#!/usr/bin/perl

########################################################################
# HTTP API MQAPI functions plugin
#
# This plugin provides the core HTTP API methods for Mosquitto
# authentication. It requires the ApiHttp plugin to be previously loaded.

package OVMS::Server::ApiHttpMqapi;

use strict;
use warnings;
use Carp;

use AnyEvent;
use AnyEvent::Log;
use OVMS::Server::Core;
use OVMS::Server::Plugin;

use Exporter qw(import);

our @EXPORT = qw();

# API: HTTP

my $me;                # Reference to our singleton object
my $mqtt_superuser;    # Superuser defined in the config

if (!PluginLoaded('ApiHttp'))
  {
  AE::log error => "Error: ApiHttp MUST be loaded before this plugin";
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

  $mqtt_superuser = MyConfig()->val('mqtt','superuser');              # MQTT superuser

  FunctionCall('HttpServerRegisterCallback','/mqapi/auth', \&http_request_in_mqapi_auth);
  FunctionCall('HttpServerRegisterCallback','/mqapi/superuser', \&http_request_in_mqapi_superuser);
  FunctionCall('HttpServerRegisterCallback','/mqapi/acl', \&http_request_in_mqapi_acl);

  return $self;
  }

sub init
  {
  my ($self) = @_;
  }

########################################################
# API HTTP server plugin methods

sub http_request_in_mqapi_auth
  {
  my ($httpd, $req) = @_;

  my $method = $req->method;
  if ($method ne 'POST')
    {
    $req->respond ( [404, 'Unrecongised API call', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Unrecognised API call\n"] );
    $httpd->stop_request;
    return;
    }

  my $p_username = $req->parm('username');
  my $p_password = $req->parm('password');
  my $p_topic    = $req->parm('topic');
  my $p_acc      = $req->parm('acc');

  if ((defined $p_username)&&(defined $p_password))
    {
    my $permissions = FunctionCall('Authenticate',$p_username,$p_password);
    if (($permissions ne '')&&(IsPermitted($permissions,'v3','mqtt')))
      {
      AE::log info => join(' ','http','-','-',$req->client_host.':'.$req->client_port,'mqapi/auth',$p_username,'SUCCESS');
      $req->respond ( [200, 'Authentication OK', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, ''] );
      $httpd->stop_request;
      return;
      }
    }

  AE::log info => join(' ','http','-','-',$req->client_host.':'.$req->client_port,'mqapi/auth',$p_username,'FAILED');
  $req->respond ( [403, 'Authentication FAILED', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, ''] );
  $httpd->stop_request;
  }

sub http_request_in_mqapi_superuser
  {
  my ($httpd, $req) = @_;

  my $method = $req->method;
  if ($method ne 'POST')
    {
    $req->respond ( [404, 'Unrecongised API call', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Unrecognised API call\n"] );
    $httpd->stop_request;
    return;
    }

  my $p_username = $req->parm('username');

  if ((!defined $p_username)||($p_username eq ''))
    {
    $req->respond ( [404, 'Username required', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Username required\n"] );
    $httpd->stop_request;
    return;
    }

  if ((!defined $mqtt_superuser)||($mqtt_superuser eq ''))
    {
    AE::log info => join(' ','http','-','-',$req->client_host.':'.$req->client_port,'mqapi/superuser',$p_username,'NOSUPERUSER');
    $req->respond ( [403, 'Not a superuser', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, ''] );
    }
  else
    {
    if ((defined $p_username)&&($p_username eq $mqtt_superuser))
      {
      AE::log info => join(' ','http','-','-',$req->client_host.':'.$req->client_port,'mqapi/superuser',$p_username,'SUPERUSER');
      $req->respond ( [200, 'Is a superuser', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, ''] );
      }
    else
      {
      AE::log info => join(' ','http','-','-',$req->client_host.':'.$req->client_port,'mqapi/superuser',$p_username,'NORMALUSER');
      $req->respond ( [403, 'Not a superuser', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, ''] );
      }
    }

  $httpd->stop_request;
  }

sub http_request_in_mqapi_acl
  {
  my ($httpd, $req) = @_;

  my $method = $req->method;
  if ($method ne 'POST')
    {
    $req->respond ( [404, 'Unrecongised API call', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Unrecognised API call\n"] );
    $httpd->stop_request;
    return;
    }

  my $p_username = $req->parm('username');
  my $p_topic    = $req->parm('topic');
  my $p_clientid = $req->parm('clientid');
  my $p_acc      = $req->parm('acc');

  if ((defined $mqtt_superuser)&&($mqtt_superuser ne '')&&
      (defined $p_username)&&($p_username eq $mqtt_superuser))
    {
    AE::log info => join(' ','http','-','-',$req->client_host.':'.$req->client_port,'mqapi/acl',$p_username, $p_topic,'PERMIT');
    $req->respond ( [200, 'Superuser acl is permitted', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, ''] );
    $httpd->stop_request;
    return;
    }

  if ((defined $p_username)&&(defined $p_topic)&&
      (substr($p_topic,0,length($p_username)+6) eq 'ovms/'.$p_username.'/'))
    {
    AE::log info => join(' ','http','-','-',$req->client_host.':'.$req->client_port,'mqapi/acl',$p_username, $p_topic, 'PERMIT');
    $req->respond ( [200, 'Access granted', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, ''] );
    }
  else
    {
    AE::log info => join(' ','http','-','-',$req->client_host.':'.$req->client_port,'mqapi/acl',$p_username, $p_topic, 'DENY');
    $req->respond ( [403, 'Access denied', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, ''] );
    }

  $httpd->stop_request;
  }

1;
