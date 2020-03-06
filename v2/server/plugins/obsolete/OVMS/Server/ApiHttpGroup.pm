#!/usr/bin/perl

########################################################################
# HTTP API GROUP functions plugin
#
# This plugin provides the core HTTP API methods for GROUP support.
# It requires the ApiHttp plugin to be previously loaded.

package OVMS::Server::ApiHttpGroup;

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

  FunctionCall('HttpServerRegisterCallback','/group', \&http_request_in_group);

  return $self;
  }

sub init
  {
  my ($self) = @_;
  }

########################################################
# API HTTP server plugin methods

sub http_request_in_group
  {
  my ($httpd, $req) = @_;

  AE::log info => join(' ','http','-','-',$req->client_host.':'.$req->client_port,'-',$req->method,$req->url);

  my $id = $req->parm('id');

  my @result;

  push @result,<<"EOT";
<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
<Document>
  <name>Open Vehicles KML</name>
  <Style id="icon">
    <IconStyle>
      <Icon>
        <href>http://www.stegen.com/pub/teslapin.png</href>
      </Icon>
    </IconStyle>
  </Style>
EOT

if (defined $group_msgs{$id})
  {
  foreach (sort keys %{$group_msgs{$id}})
    {
    my ($vehicleid,$groupmsg) = ($_,$group_msgs{$id}{$_});
    my ($soc,$speed,$direction,$altitude,$gpslock,$stalegps,$latitude,$longitude) = split(/,/,$groupmsg);

    push @result,<<"EOT";
  <Placemark>
    <name>$vehicleid</name>
    <description>$vehicleid</description>
    <styleUrl>#icon</styleUrl>
    <Point>
      <coordinates>$longitude,$latitude</coordinates>
    </Point>
  </Placemark>
EOT
    }
  }

  push @result,<<"EOT";
</Document>
</kml>
EOT

  $req->respond([
      200, 'OK', {
        'Content-Type'  => 'Content-Type: application/vnd.google-earth.kml+xml'
      },
      join("\n",@result)
   ]);
  $httpd->stop_request;
  }

1;
