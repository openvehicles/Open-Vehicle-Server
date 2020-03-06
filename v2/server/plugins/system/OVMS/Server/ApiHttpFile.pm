#!/usr/bin/perl

########################################################################
# HTTP API FILE functions plugin
#
# This plugin provides the core HTTP API methods for file download from
# a public directory. It requires the ApiHttp plugin to be previously loaded.


package OVMS::Server::ApiHttpFile;

use strict;
use warnings;
use Carp;

use AnyEvent;
use AnyEvent::Log;
use OVMS::Server::Plugin;

use Exporter qw(import);

our @EXPORT = qw();

# API: HTTP

my $me; # Reference to our singleton object

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

  FunctionCall('HttpServerRegisterCallback','/file', \&http_request_in_file);

  return $self;
  }

sub init
  {
  my ($self) = @_;
  }

########################################################
# API HTTP server plugin methods

sub http_request_in_file
  {
  my ($httpd, $req) = @_;

  AE::log info => join(' ','http','-','-',$req->client_host.':'.$req->client_port,'-',$req->method,$req->url);

  my $filepath = $1 if ($req->url =~ /^\/file\/([a-zA-Z0-9\-\_\.]+)$/);

  if ((defined $filepath)&&(-f "httpfiles/$filepath"))
    {
    open my $fp,'<',"httpfiles/$filepath";
    $_ = <$fp>; chop;
    my $contenttype = $_;
    AE::log info => join(' ','http','-','-',$req->client_host.':'.$req->client_port,'-','start file transfer');
    $req->respond ({ content => [$contenttype, sub {
      my ($data_cb) = @_;

      if (!defined $data_cb)
        {
        AE::log info => join(' ','http','-','-',$req->client_host.':'.$req->client_port,'-','finished file transfer');
        close $fp;
        return;
        }
      else
        {
        my $buf;
        read $fp,$buf,16384;
        AE::log info => join(' ','http','-','-',$req->client_host.':'.$req->client_port,'-','file transfer blob: ',length($buf),'bytes');
        &$data_cb($buf);
        }
      } ]});
    }
  else
    {
    $req->respond (
                    [404, 'not found', { 'Content-Type' => 'text/plain' }, "not found\n"]
                 );
    }

  $httpd->stop_request;
  }

1;
