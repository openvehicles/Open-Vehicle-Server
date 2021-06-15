#!/usr/bin/perl

########################################################################
# HTTP API core functions plugin
#
# This plugin provides the core HTTP API methods for OVMS. It requires
# the ApiHttp plugin to be previously loaded.

package OVMS::Server::ApiHttpCore;

use strict;
use warnings;
use Carp;

use AnyEvent;
use AnyEvent::Log;
use Data::UUID;
use Digest::SHA;
use OVMS::Server::Core;
use OVMS::Server::Plugin;
use Time::Piece;

use Exporter qw(import);

our @EXPORT = qw();

# API: HTTP

my $me;                           # Reference to our singleton object
my %http_request_api_call;        # Map of HTTP API calls
my %api_conns;                    # API sessions
my $api_tim;                      # API cleanup timer

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

  FunctionCall('HttpServerRegisterCallback','/api', \&http_request_in_api);

  RegisterFunction('ApiConnectionCount', \&api_connection_count);
  # AE::log info => "- - - HTTP API core has "
  #               . (scalar keys %http_request_api_noauth) . " noauth callback(s), and "
  #               . (scalar keys %http_request_api_auth) . " auth callback(s)";

  # Session cleanup tickers
  $api_tim = AnyEvent->timer (after => 10, interval => 10, cb => \&api_tim);

  return $self;
  }

sub init
  {
  my ($self) = @_;
  }

sub api_connection_count
  {
  my ($vehicleid) = @_;

  return scalar keys %api_conns;
  }

sub api_delete_session
  {
  my ($sessionid) = @_;

  my $username = $api_conns{$sessionid}{'owner'};

  foreach my $row (FunctionCall('DbGetOwnerCars', $username))
    {
    my $vehicleid = $row->{'vehicleid'};
    if (defined AppConnection($username, $vehicleid, 'http:'.$sessionid))
      {
      AppDisconnect($username, $vehicleid, 'http:'.$sessionid);
      CarTransmit($username, $vehicleid, 'v2', 'Z', AppConnectionCount($username, $vehicleid));
      }
    }

  delete $api_conns{$sessionid};
  }

sub api_tim
  {
  my $timeout_api  = MyConfig()->val('server','timeout_api',60*2);

  foreach my $session (keys %api_conns)
    {
    my $lastused = $api_conns{$session}{'sessionused'};
    my $expire = AnyEvent->now - $timeout_api;
    if ($lastused < $expire)
      {
      api_delete_session($session);
      AE::log info => join(' ','http','-',$session,'-','session timeout');
      }
    }

  FunctionCall('InfoCount', 'HTTPAPI_sessions', (scalar keys %api_conns));
  }

########################################################
# API HTTP server


########################################################
# /api/cookie - Login/Logout

# GET     /api/cookie                             Login and return a session cookie
BEGIN { $http_request_api_call{'GET:cookie'} =    [ \&http_request_api_cookie_login, 'session' ]; }
sub http_request_api_cookie_login
  {
  my ($httpd, $req, $sessionid, $username, $permissions, @rest) = @_;

  api_delete_session($sessionid) if (defined $api_conns{$sessionid});
  my $ug = new Data::UUID;
  $sessionid =  $ug->create_str();

  $api_conns{$sessionid}{'owner'} = $username;
  $api_conns{$sessionid}{'permissions'} = $permissions;
  $api_conns{$sessionid}{'sessionused'} = AnyEvent->now;

  FunctionCall('InfoCount', 'HTTPAPI_sessions', (scalar keys %api_conns));

  AE::log info => join(' ','http','-',$sessionid,$req->client_host.':'.$req->client_port,'session created');

  $req->respond (  [200, 'Ok', { 'Content-Type' => 'text/plain', 'Set-Cookie' => "ovmsapisession=$sessionid", 'Access-Control-Allow-Origin' => '*' }, "Login ok\n"] );
  $httpd->stop_request;
  return;
  }

# DELETE  /api/cookie                             Delete the session cookie and logout
BEGIN { $http_request_api_call{'DELETE:cookie'} = [ \&http_request_api_cookie_logout, 'session' ]; }
sub http_request_api_cookie_logout
  {
  my ($httpd,$req,$sessionid,@rest) = @_;

  api_delete_session($sessionid);
  FunctionCall('InfoCount', 'HTTPAPI_sessions', (scalar keys %api_conns));

  AE::log info => join(' ','http','-',$sessionid,$req->client_host.':'.$req->client_port,'session destroyed (on request)');

  $req->respond ( [200, 'Ok', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Logout ok\n"] );
  $httpd->stop_request;
  }

########################################################
# /api/token - API token management

# GET     /api/token                              Return a list of API tokens
BEGIN { $http_request_api_call{'GET:token'} =     [ \&http_request_api_token_list, 'token.admin','admin' ]; }
sub http_request_api_token_list
  {
  my ($httpd, $req, $sessionid, $username, $permissions, @rest) = @_;

  my @result;
  foreach my $row (FunctionCall('DbGetOwnerTokens', $username))
    {
    push @result, $row;
    }

  my $json = JSON::XS->new->utf8->canonical->encode (\@result) . "\n";
  $req->respond ( [200, 'Ok', { 'Content-Type' => 'application/json', 'Access-Control-Allow-Origin' => '*' }, $json] );
  $httpd->stop_request;
  }

# POST    /api/token                              Obtain an API token
BEGIN { $http_request_api_call{'POST:token'} =    [ \&http_request_api_token_obtain, 'token.admin','admin' ]; }
sub http_request_api_token_obtain
  {
  my ($httpd, $req, $sessionid, $username, $permissions, @rest) = @_;

  my $application = $req->parm('application'); $application='notspecified' if (!defined $application);
  my $purpose = $req->parm('purpose'); $purpose='notspecified' if (!defined $purpose);
  my $permit = $req->parm('permit'); $permit='auth' if (!defined $permit);

  my $random;
  if (open my $r, '<', '/dev/urandom')
    {
    read $r,$random,512;
    close $r;
    }
  while (length($random) < 512)
    {
    $random .= rand(255);
    }
  my $token = Digest::SHA::sha256_hex($random);

  FunctionCall('DbSaveToken', $username, $token, $application, $purpose, $permit);

  my %result = ( owner => $username,
                 token => $token,
                 application => $application,
                 purpose => $purpose,
                 permit => $permit
                 );

  my $json = JSON::XS->new->utf8->canonical->encode (\%result) . "\n";
  $req->respond ( [201, 'Created', { 'Content-Type' => 'application/json', 'Access-Control-Allow-Origin' => '*' }, $json] );

  $httpd->stop_request;
  return;
  }

# DELETE  /api/token                              Delete the specified api token
BEGIN { $http_request_api_call{'DELETE:token'} =  [ \&http_request_api_token_delete, 'token.admin','admin' ]; }
sub http_request_api_token_delete
  {
  my ($httpd, $req, $sessionid, $username, $permissions, @rest) = @_;

  my ($token) = @rest;

  if (defined $token)
    {
    FunctionCall('DbDeleteToken', $username, $token);

    my %result = ( owner => $username,
                   token => $token);

    my $json = JSON::XS->new->utf8->canonical->encode (\%result) . "\n";
    $req->respond ( [200, 'Ok', { 'Content-Type' => 'application/json', 'Access-Control-Allow-Origin' => '*' }, $json] );

    $httpd->stop_request;
    return;
    }
  else
    {
    $req->respond ( [404, 'Token missing', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Token not specified\n"] );
    $httpd->stop_request;
    return;
    }
  }

########################################################
# /api/vehicle - Vehicle record management

# GET     /api/vehicles                           Return alist of registered vehicles
BEGIN { $http_request_api_call{'GET:vehicles'} =  [ \&http_request_api_vehicles ]; }
sub http_request_api_vehicles
  {
  my ($httpd, $req, $sessionid, $username, $permissions, @rest) = @_;

  my @result;
  foreach my $row (FunctionCall('DbGetOwnerCars', $username))
    {
    my $vehicleid = $row->{'vehicleid'};
    my $carcount = CarConnectionCount($username, $vehicleid);
    my $appcount = AppConnectionCount($username, $vehicleid);
    my $btccount = BatchConnectionCount($username, $vehicleid);

    my %h = ( 'id'=>$vehicleid, 'v_net_connected'=>$carcount, 'v_apps_connected'=>$appcount, 'v_btcs_connected'=>$btccount );
    push @result, \%h;
    }

  my $json = JSON::XS->new->utf8->canonical->encode (\@result) . "\n";
  $req->respond ( [200, 'Ok', { 'Content-Type' => 'application/json', 'Access-Control-Allow-Origin' => '*' }, $json] );
  $httpd->stop_request;
  }

# GET     /api/vehicle/<VEHICLEID>                Connect to, and return vehicle information
BEGIN { $http_request_api_call{'GET:vehicle'} =   [ \&http_request_api_vehicle_get ]; }
sub http_request_api_vehicle_get
  {
  my ($httpd, $req, $sessionid, $username, $permissions, @rest) = @_;

  my ($vehicleid) = @rest;

  if ( ! FunctionCall('DbHasVehicle', $username, $vehicleid) )
    {
    AE::log info => join(' ','http','-',$sessionid,$req->client_host.':'.$req->client_port,'Forbidden access',$vehicleid);
    $req->respond ( [403, 'Forbidden', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Forbidden\n"] );
    $httpd->stop_request;
    return;
    }

  my %result;

  # Register API APP:
  AE::log info => join(' ','http','-',$sessionid,$req->client_host.':'.$req->client_port,'Vehicle connect',$vehicleid);
  my $prevappcnt = AppConnectionCount($username, $vehicleid);
  AppConnect($username, $vehicleid, 'http:'.$sessionid);

  # Notify car:
  CarTransmit($username, $vehicleid, 'v2', 'Z', AppConnectionCount($username, $vehicleid));

  # Return peer status:
  $result{'v_net_connected'} = CarConnectionCount($username, $vehicleid);
  $result{'v_apps_connected'} = AppConnectionCount($username, $vehicleid);
  $result{'v_btcs_connected'} = BatchConnectionCount($username, $vehicleid);
  $result{'v_first_peer'} = ($prevappcnt == 0) ? 1 : 0;

  my $rec = &api_vehiclerecord($username, $vehicleid, 'S');
  if (defined $rec && defined $rec->{'m_msgtime'})
    {
    my $t = Time::Piece->strptime($rec->{'m_msgtime'}, "%Y-%m-%d %H:%M:%S");
    $result{'m_msgtime_s'} = $rec->{'m_msgtime'};
    $result{'m_msgage_s'} = time() - $t->epoch;
    }

  my $json = JSON::XS->new->utf8->canonical->encode (\%result) . "\n";
  $req->respond ( [200, 'Ok', { 'Content-Type' => 'application/json', 'Access-Control-Allow-Origin' => '*' }, $json] );
  $httpd->stop_request;
  }

# DELETE  /api/vehicle/<VEHICLEID>                 Disconnect from vehicle
BEGIN { $http_request_api_call{'DELETE:vehicle'} = [ \&http_request_api_vehicle_delete ]; }
sub http_request_api_vehicle_delete
  {
  my ($httpd, $req, $sessionid, $username, $permissions, @rest) = @_;

  my ($vehicleid) = @rest;

  if ( ! FunctionCall('DbHasVehicle', $username, $vehicleid) )
    {
    AE::log info => join(' ','http','-',$sessionid,$req->client_host.':'.$req->client_port,'Forbidden access',$vehicleid);
    $req->respond ( [403, 'Forbidden', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Forbidden\n"] );
    $httpd->stop_request;
    return;
    }

  my %result;

  # Logout API APP:
  AE::log info => join(' ','http','-',$sessionid,$req->client_host.':'.$req->client_port,'Vehicle disconnect',$vehicleid);
  AppDisconnect($username, $vehicleid, 'http:'.$sessionid);

  # Notify car:
  CarTransmit($username, $vehicleid, 'v2', 'Z', AppConnectionCount($username, $vehicleid));

  $req->respond ( [200, 'Ok', { 'Content-Type' => 'application/json', 'Access-Control-Allow-Origin' => '*' }, "Disconnect OK\n"] );
  $httpd->stop_request;
  }

########################################################
# /api/protocol - Raw protocol records

# GET     /api/protocol/<VEHICLEID>               Return raw protocol records (no vehicle connection)
BEGIN { $http_request_api_call{'GET:protocol'} =  [ \&http_request_api_protocol ]; }
sub http_request_api_protocol
  {
  my ($httpd, $req, $sessionid, $username, $permissions, @rest) = @_;

  my ($vehicleid) = @rest;

  if ( ! FunctionCall('DbHasVehicle', $username, $vehicleid) )
    {
    AE::log info => join(' ','http','-',$sessionid,$req->client_host.':'.$req->client_port,'Forbidden access',$vehicleid);
    $req->respond ( [403, 'Forbidden', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Forbidden\n"] );
    $httpd->stop_request;
    return;
    }

  my @result;
  foreach my $row (FunctionCall('DbGetMessages', $username, $vehicleid))
    {
    my %h;
    foreach (qw(m_msgtime m_paranoid m_ptoken m_code m_msg))
      {
      $h{$_} = $row->{$_};
      }
    push @result, \%h;
    }

  my $json = JSON::XS->new->utf8->canonical->encode (\@result) . "\n";
  $req->respond ( [200, 'Ok', { 'Content-Type' => 'application/json', 'Access-Control-Allow-Origin' => '*' }, $json] );
  $httpd->stop_request;
  }

########################################################
# /api/status - Vehicle status

# GET	/api/status/<VEHICLEID>		                	Return vehicle status
BEGIN { $http_request_api_call{'GET:status'} =    [ \&http_request_api_status ]; }
sub http_request_api_status
  {
  my ($httpd, $req, $sessionid, $username, $permissions, @rest) = @_;

  my ($vehicleid) = @rest;


  if ( ! FunctionCall('DbHasVehicle', $username, $vehicleid) )
    {
    AE::log info => join(' ','http','-',$sessionid,$req->client_host.':'.$req->client_port,'Forbidden access',$vehicleid);
    $req->respond ( [403, 'Forbidden', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Forbidden\n"] );
    $httpd->stop_request;
    return;
    }

  my $rec = &api_vehiclerecord($username, $vehicleid, 'S');
  my %result;
  if (defined $rec)
    {
    if ($rec->{'m_paranoid'})
      {
      $req->respond ( [502, 'Bad Gateway', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Paranoid vehicles not supported by api\n"] );
      $httpd->stop_request;
      return;
      }
    my ($soc,$units,$linevoltage,$chargecurrent,$chargestate,$chargemode,$idealrange,$estimatedrange,
        $chargelimit,$chargeduration,$chargeb4,$chargekwh,$chargesubstate,$chargestateN,$chargemodeN,
        $chargetimer,$chargestarttime,$chargetimerstale,$cac100,
        $charge_etr_full,$charge_etr_limit,$charge_limit_range,$charge_limit_soc,
        $cooldown_active,$cooldown_tbattery,$cooldown_timelimit,
        $charge_estimate,$charge_etr_range,$charge_etr_soc,$idealrange_max,
        $chargetype,$chargepower,$battvoltage,$soh,$chargepowerinput,$chargerefficiency)
        = split /,/,$rec->{'m_msg'};
    my $t = Time::Piece->strptime($rec->{'m_msgtime'}, "%Y-%m-%d %H:%M:%S");
    $result{'m_msgtime_s'} = $rec->{'m_msgtime'};
    $result{'m_msgage_s'} = time() - $t->epoch;
    $result{'soc'} = $soc;
    $result{'units'} = $units;
    $result{'idealrange'} = $idealrange;
    $result{'idealrange_max'} = $idealrange_max;
    $result{'estimatedrange'} = $estimatedrange,
    $result{'mode'} = $chargemode;
    $result{'chargestate'} = $chargestate;
    $result{'cac100'} = $cac100;
    $result{'soh'} = $soh;
    $result{'cooldown_active'} = $cooldown_active;
    }
  $rec= &api_vehiclerecord($username, $vehicleid, 'D');
  if (defined $rec)
    {
    if (! $rec->{'m_paranoid'})
      {
      my ($doors1,$doors2,$lockunlock,$tpem,$tmotor,$tbattery,$trip,$odometer,$speed,$parktimer,$ambient,
          $doors3,$staletemps,$staleambient,$vehicle12v,$doors4,$vehicle12v_ref,$doors5,$tcharger,
          $vehicle12v_current,$cabin_temp)
          = split /,/,$rec->{'m_msg'};
      my $t = Time::Piece->strptime($rec->{'m_msgtime'}, "%Y-%m-%d %H:%M:%S");
      $result{'m_msgtime_d'} = $rec->{'m_msgtime'};
      $result{'m_msgage_d'} = time() - $t->epoch;
      $result{'fl_dooropen'} =   $doors1 & 0b00000001;
      $result{'fr_dooropen'} =   $doors1 & 0b00000010;
      $result{'cp_dooropen'} =   $doors1 & 0b00000100;
      $result{'pilotpresent'} =  $doors1 & 0b00001000;
      $result{'charging'} =      $doors1 & 0b00010000;
      $result{'handbrake'} =     $doors1 & 0b01000000;
      $result{'caron'} =         $doors1 & 0b10000000;
      $result{'carlocked'} =     $doors2 & 0b00001000;
      $result{'valetmode'} =     $doors2 & 0b00010000;
      $result{'bt_open'} =       $doors2 & 0b01000000;
      $result{'tr_open'} =       $doors2 & 0b10000000;
      $result{'temperature_pem'} = $tpem;
      $result{'temperature_motor'} = $tmotor;
      $result{'temperature_battery'} = $tbattery;
      $result{'temperature_charger'} = $tcharger;
      $result{'temperature_cabin'} = $cabin_temp;
      $result{'tripmeter'} = $trip;
      $result{'odometer'} = $odometer;
      $result{'speed'} = $speed;
      $result{'parkingtimer'} = $parktimer;
      $result{'temperature_ambient'} = $ambient;
      $result{'carawake'} =      $doors3 & 0b00000010;
      $result{'staletemps'} = $staletemps;
      $result{'staleambient'} = $staleambient;
      $result{'charging_12v'} =  $doors5 & 0b00010000;
      $result{'vehicle12v'} = $vehicle12v;
      $result{'vehicle12v_ref'} = $vehicle12v_ref;
      $result{'vehicle12v_current'} = $vehicle12v_current;
      $result{'alarmsounding'} = $doors4 & 0b00000100;
      }
    }

  my $json = JSON::XS->new->utf8->canonical->encode (\%result) . "\n";
  $req->respond ( [200, 'Ok', { 'Content-Type' => 'application/json', 'Access-Control-Allow-Origin' => '*' }, $json] );
  $httpd->stop_request;
  }

########################################################
# /api/tpms - TPMS status

# GET	/api/tpms/<VEHICLEID>			              Return tpms status
BEGIN { $http_request_api_call{'GET:tpms'} =  [ \&http_request_api_tpms ]; }
sub http_request_api_tpms
  {
  my ($httpd, $req, $sessionid, $username, $permissions, @rest) = @_;

  my ($vehicleid) = @rest;

  if ( ! FunctionCall('DbHasVehicle', $username, $vehicleid) )
    {
    AE::log info => join(' ','http','-',$sessionid,$req->client_host.':'.$req->client_port,'Forbidden access',$vehicleid);
    $req->respond ( [403, 'Forbidden', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Forbidden\n"] );
    $httpd->stop_request;
    return;
    }

  my $rec = &api_vehiclerecord($username, $vehicleid, 'W');
  my %result;
  if (defined $rec)
    {
    if ($rec->{'m_paranoid'})
      {
      $req->respond ( [502, 'Bad Gateway', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Paranoid vehicles not supported by api\n"] );
      $httpd->stop_request;
      return;
      }
    my ($fr_pressure,$fr_temp,$rr_pressure,$rr_temp,$fl_pressure,$fl_temp,$rl_pressure,$rl_temp,$staletpms) = split /,/,$rec->{'m_msg'};
    my $t = Time::Piece->strptime($rec->{'m_msgtime'}, "%Y-%m-%d %H:%M:%S");
    $result{'m_msgtime_w'} = $rec->{'m_msgtime'};
    $result{'m_msgage_w'} = time() - $t->epoch;
    $result{'fr_pressure'} = $fr_pressure;
    $result{'fr_temperature'} = $fr_temp;
    $result{'rr_pressure'} = $rr_pressure;
    $result{'rr_temperature'} = $rr_temp;
    $result{'fl_pressure'} = $fl_pressure;
    $result{'fl_temperature'} = $fl_temp;
    $result{'rl_pressure'} = $rl_pressure;
    $result{'rl_temperature'} = $rl_temp;
    $result{'staletpms'} = $staletpms;
    }

  my $json = JSON::XS->new->utf8->canonical->encode (\%result) . "\n";
  $req->respond ( [200, 'Ok', { 'Content-Type' => 'application/json', 'Access-Control-Allow-Origin' => '*' }, $json] );
  $httpd->stop_request;
  }

########################################################
# /api/location - Vehicle location

# GET	/api/location/<VEHICLEID>		                  Return vehicle location
BEGIN { $http_request_api_call{'GET:location'} =    [ \&http_request_api_location ]; }
sub http_request_api_location
  {
  my ($httpd, $req, $sessionid, $username, $permissions, @rest) = @_;

  my ($vehicleid) = @rest;

  if ( ! FunctionCall('DbHasVehicle', $username, $vehicleid) )
    {
    AE::log info => join(' ','http','-',$sessionid,$req->client_host.':'.$req->client_port,'Forbidden access',$vehicleid);
    $req->respond ( [403, 'Forbidden', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Forbidden\n"] );
    $httpd->stop_request;
    return;
    }

  my $rec = &api_vehiclerecord($username, $vehicleid, 'L');
  my %result;
  if (defined $rec)
    {
    if ($rec->{'m_paranoid'})
      {
      $req->respond ( [502, 'Bad Gateway', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Paranoid vehicles not supported by api\n"] );
      $httpd->stop_request;
      return;
      }
    my ($latitude,$longitude,$direction,$altitude,$gpslock,$stalegps,$speed,$tripmeter,
      $drivemode,$power,$energyused,$energyrecd,$invpower,$invefficiency) = split /,/,$rec->{'m_msg'};
    my $t = Time::Piece->strptime($rec->{'m_msgtime'}, "%Y-%m-%d %H:%M:%S");
    $result{'m_msgtime_l'} = $rec->{'m_msgtime'};
    $result{'m_msgage_l'} = time() - $t->epoch;
    $result{'latitude'} = $latitude;
    $result{'longitude'} = $longitude;
    $result{'direction'} = $direction;
    $result{'altitude'} = $altitude;
    $result{'gpslock'} = $gpslock;
    $result{'stalegps'} = $stalegps;
    $result{'speed'} = $speed;
    $result{'tripmeter'} = $tripmeter;
    $result{'drivemode'} = $drivemode;
    $result{'power'} = $power;
    $result{'energyused'} = $energyused;
    $result{'energyrecd'} = $energyrecd;
    $result{'invpower'} = $invpower;
    $result{'invefficiency'} = $invefficiency;
    }

  my $json = JSON::XS->new->utf8->canonical->encode (\%result) . "\n";
  $req->respond ( [200, 'Ok', { 'Content-Type' => 'application/json', 'Access-Control-Allow-Origin' => '*' }, $json] );
  $httpd->stop_request;
  }

########################################################
# /api/charge - Vehicle charge status and management

# GET	/api/charge/<VEHICLEID>			               Return vehicle charge status
BEGIN { $http_request_api_call{'GET:charge'} =   [ \&http_request_api_charge_get ]; }
sub http_request_api_charge_get
  {
  my ($httpd, $req, $sessionid, $username, $permissions, @rest) = @_;

  my ($vehicleid) = @rest;

  if ( ! FunctionCall('DbHasVehicle', $username, $vehicleid) )
    {
    AE::log info => join(' ','http','-',$sessionid,$req->client_host.':'.$req->client_port,'Forbidden access',$vehicleid);
    $req->respond ( [403, 'Forbidden', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Forbidden\n"] );
    $httpd->stop_request;
    return;
    }

  my $rec = &api_vehiclerecord($username, $vehicleid, 'S');
  my %result;
  if (defined $rec)
    {
    if ($rec->{'m_paranoid'})
      {
      $req->respond ( [502, 'Bad Gateway', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Paranoid vehicles not supported by api\n"] );
      $httpd->stop_request;
      return;
      }
    my ($soc,$units,$linevoltage,$chargecurrent,$chargestate,$chargemode,$idealrange,$estimatedrange,
        $chargelimit,$chargeduration,$chargeb4,$chargekwh,$chargesubstate,$chargestateN,$chargemodeN,
        $chargetimer,$chargestarttime,$chargetimerstale,$cac100,
        $charge_etr_full,$charge_etr_limit,$charge_limit_range,$charge_limit_soc,
        $cooldown_active,$cooldown_tbattery,$cooldown_timelimit,
        $charge_estimate,$charge_etr_range,$charge_etr_soc,$idealrange_max,
        $chargetype,$chargepower,$battvoltage,$soh,$chargepowerinput,$chargerefficiency)
        = split /,/,$rec->{'m_msg'};
    my $t = Time::Piece->strptime($rec->{'m_msgtime'}, "%Y-%m-%d %H:%M:%S");
    $result{'m_msgtime_s'} = $rec->{'m_msgtime'};
    $result{'m_msgage_s'} = time() - $t->epoch;
    $result{'linevoltage'} = $linevoltage;
    $result{'battvoltage'} = $battvoltage;
    $result{'chargecurrent'} = $chargecurrent;
    $result{'chargepower'} = $chargepower;
    $result{'chargepowerinput'} = $chargepowerinput;
    $result{'chargerefficiency'} = $chargerefficiency;
    $result{'chargetype'} = $chargetype;
    $result{'chargestate'} = $chargestate;
    $result{'soc'} = $soc;
    $result{'units'} = $units;
    $result{'idealrange'} = $idealrange;
    $result{'estimatedrange'} = $estimatedrange,
    $result{'mode'} = $chargemode;
    $result{'chargelimit'} = $chargelimit;
    $result{'chargeduration'} = $chargeduration;
    $result{'chargeb4'} = $chargeb4;
    $result{'chargekwh'} = $chargekwh;
    $result{'chargesubstate'} = $chargesubstate;
    $result{'chargetimermode'} = $chargetimer;
    $result{'chargestarttime'} = $chargestarttime;
    $result{'chargetimerstale'} = $chargetimerstale;
    $result{'cac100'} = $cac100;
    $result{'soh'} = $soh;
    $result{'charge_etr_full'} = $charge_etr_full;
    $result{'charge_etr_limit'} = $charge_etr_limit;
    $result{'charge_limit_range'} = $charge_limit_range;
    $result{'charge_limit_soc'} = $charge_limit_soc;
    $result{'cooldown_active'} = $cooldown_active;
    $result{'cooldown_tbattery'} = $cooldown_tbattery;
    $result{'cooldown_timelimit'} = $cooldown_timelimit;
    $result{'charge_estimate'} = $charge_estimate;
    $result{'charge_etr_range'} = $charge_etr_range;
    $result{'charge_etr_soc'} = $charge_etr_soc;
    $result{'idealrange_max'} = $idealrange_max;
    }
  $rec= &api_vehiclerecord($username, $vehicleid, 'D');
  if (defined $rec)
    {
    if (! $rec->{'m_paranoid'})
      {
      my ($doors1,$doors2,$lockunlock,$tpem,$tmotor,$tbattery,$trip,$odometer,$speed,$parktimer,$ambient,
          $doors3,$staletemps,$staleambient,$vehicle12v,$doors4,$vehicle12v_ref,$doors5,$tcharger,
          $vehicle12v_current,$cabin_temp)
          = split /,/,$rec->{'m_msg'};
      my $t = Time::Piece->strptime($rec->{'m_msgtime'}, "%Y-%m-%d %H:%M:%S");
      $result{'m_msgtime_d'} = $rec->{'m_msgtime'};
      $result{'m_msgage_d'} = time() - $t->epoch;
      $result{'cp_dooropen'} =   $doors1 & 0b00000100;
      $result{'pilotpresent'} =  $doors1 & 0b00001000;
      $result{'charging'} =      $doors1 & 0b00010000;
      $result{'caron'} =         $doors1 & 0b10000000;
      $result{'temperature_pem'} = $tpem;
      $result{'temperature_motor'} = $tmotor;
      $result{'temperature_battery'} = $tbattery;
      $result{'temperature_charger'} = $tcharger;
      $result{'temperature_ambient'} = $ambient;
      $result{'temperature_cabin'} = $cabin_temp;
      $result{'carawake'} =      $doors3 & 0b00000010;
      $result{'staletemps'} = $staletemps;
      $result{'staleambient'} = $staleambient;
      $result{'charging_12v'} =  $doors5 & 0b00010000;
      $result{'vehicle12v'} = $vehicle12v;
      $result{'vehicle12v_ref'} = $vehicle12v_ref;
      $result{'vehicle12v_current'} = $vehicle12v_current;
      }
    }

  my $json = JSON::XS->new->utf8->canonical->encode (\%result) . "\n";
  $req->respond ( [200, 'Ok', { 'Content-Type' => 'application/json', 'Access-Control-Allow-Origin' => '*' }, $json] );
  $httpd->stop_request;
  }

# PUT	/api/charge/<VEHICLEID>			              Set vehicle charge status
BEGIN { $http_request_api_call{'PUT:charge'} =  [ \&http_request_api_charge_put ]; }
sub http_request_api_charge_put
  {
  my ($httpd, $req, $sessionid, $username, $permissions, @rest) = @_;

  $req->respond ( [501, 'Not Implemented', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Not yet implemented\n"] );
  $httpd->stop_request;
  }

# DELETE	/api/charge/<VEHICLEID>			            Abort a vehicle charge
BEGIN { $http_request_api_call{'DELETE:charge'} = [ \&http_request_api_charge_delete ]; }
sub http_request_api_charge_delete
  {
  my ($httpd, $req, $sessionid, $username, $permissions, @rest) = @_;

  $req->respond ( [501, 'Not Implemented', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Not yet implemented\n"] );
  $httpd->stop_request;
  }

########################################################
# /api/lock - Vehicle lock control

# GET	/api/lock/<VEHICLEID>			               Return vehicle lock status
BEGIN { $http_request_api_call{'GET:lock'} =   [ \&http_request_api_lock_get ]; }
sub http_request_api_locK_get
  {
  my ($httpd, $req, $sessionid, $username, $permissions, @rest) = @_;

  $req->respond ( [501, 'Not Implemented', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Not yet implemented\n"] );
  $httpd->stop_request;
  }

# PUT	/api/lock/<VEHICLEID>		                	Lock a vehicle
BEGIN { $http_request_api_call{'PUT:lock'} =    [ \&http_request_api_lock_put ]; }
sub http_request_api_lock_put
  {
  my ($httpd, $req, $sessionid, $username, $permissions, @rest) = @_;

  $req->respond ( [501, 'Not Implemented', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Not yet implemented\n"] );
  $httpd->stop_request;
  }

# DELETE	/api/lock/<VEHICLEID>			            Unlock a vehicle
BEGIN { $http_request_api_call{'DELETE:lock'} = [ \&http_request_api_lock_delete ]; }
sub http_request_api_lock_delete
  {
  my ($httpd, $req, $sessionid, $username, $permissions, @rest) = @_;

  $req->respond ( [501, 'Not Implemented', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Not yet implemented\n"] );
  $httpd->stop_request;
  }

########################################################
# /api/valet - Vehicle valet control

# GET	/api/valet/<VEHICLEID>			            Return valet status
BEGIN { $http_request_api_call{'GET:valet'} = [ \&http_request_api_valet_get ]; }
sub http_request_api_valet_get
  {
  my ($httpd, $req, $sessionid, $username, $permissions, @rest) = @_;

  $req->respond ( [501, 'Not Implemented', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Not yet implemented\n"] );
  $httpd->stop_request;
  }

# PUT	/api/valet/<VEHICLEID>			            Enable valet mode
BEGIN { $http_request_api_call{'PUT:valet'} = [ \&http_request_api_valet_put ]; }
sub http_request_api_valet_put
  {
  my ($httpd, $req, $sessionid, $username, $permissions, @rest) = @_;

  $req->respond ( [501, 'Not Implemented', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Not yet implemented\n"] );
  $httpd->stop_request;
  }

# DELETE	/api/valet/<VEHICLEID>			           Disable valet mode
BEGIN { $http_request_api_call{'DELETE:valet'} = [ \&http_request_api_valet_delete ]; }
sub http_request_api_valet_delete
  {
  my ($httpd, $req, $sessionid, $username, $permissions, @rest) = @_;

  $req->respond ( [501, 'Not Implemented', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Not yet implemented\n"] );
  $httpd->stop_request;
  }

########################################################
# /api/features - Vehicle features

# GET	/api/features/<VEHICLEID>		               Return vehicle features
BEGIN { $http_request_api_call{'GET:features'} = [ \&http_request_api_features_get ]; }
sub http_request_api_features_get
  {
  my ($httpd, $req, $sessionid, $username, $permissions, @rest) = @_;

  $req->respond ( [501, 'Not Implemented', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Not yet implemented\n"] );
  $httpd->stop_request;
  }

# PUT	/api/feature/<VEHICLEID>	                 Set a vehicle feature
BEGIN { $http_request_api_call{'PUT:features'} = [ \&http_request_api_features_put ]; }
sub http_request_api_features_put
  {
  my ($httpd, $req, $sessionid, $username, $permissions, @rest) = @_;

  $req->respond ( [501, 'Not Implemented', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Not yet implemented\n"] );
  $httpd->stop_request;
  }

########################################################
# /api/parameters - Vehicle parameters

# GET	/api/parameters/<VEHICLEID>		               Return vehicle parameters
BEGIN { $http_request_api_call{'GET:parameters'} = [ \&http_request_api_parameters_get ]; }
sub http_request_api_parameters_get
  {
  my ($httpd, $req, $sessionid, $username, $permissions, @rest) = @_;

  $req->respond ( [501, 'Not Implemented', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Not yet implemented\n"] );
  $httpd->stop_request;
  }

# PUT	/api/parameter/<VEHICLEID>		               Set a vehicle parameter
BEGIN { $http_request_api_call{'PUT:parameters'} = [ \&http_request_api_parameters_put ]; }
sub http_request_api_parameters_put
  {
  my ($httpd, $req, $sessionid, $username, $permissions, @rest) = @_;

  $req->respond ( [501, 'Not Implemented', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Not yet implemented\n"] );
  $httpd->stop_request;
  }

########################################################
# /api/reset - Vehicle module reset

# PUT	/api/reset/<VEHICLEID>			            Reset the module in a particular vehicle
BEGIN { $http_request_api_call{'PUT:reset'} = [ \&http_request_api_reset ]; }
sub http_request_api_reset
  {
  my ($httpd, $req, $sessionid, $username, $permissions, @rest) = @_;

  $req->respond ( [501, 'Not Implemented', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Not yet implemented\n"] );
  $httpd->stop_request;
  }

########################################################
# /api/homelink - Vehicle homelink control

# PUT	/api/homelink/<VEHICLEID>		               Activate home link
BEGIN { $http_request_api_call{'PUT:homelink'} = [ \&http_request_api_homelink ]; }
sub http_request_api_homelink
  {
  my ($httpd, $req, $sessionid, $username, $permissions, @rest) = @_;

  $req->respond ( [501, 'Not Implemented', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Not yet implemented\n"] );
  $httpd->stop_request;
  }

########################################################
# /api/historical - Vehicle historical data

# GET	/api/historical/<VEHICLEID>		Request historical data summary
# GET     /api/historical/<VEHICLEID>/<DATATYPE>   Request historical data records
BEGIN { $http_request_api_call{'GET:historical'} = [ \&http_request_api_historical ]; }
sub http_request_api_historical
  {
  my ($httpd, $req, $sessionid, $username, $permissions, @rest) = @_;

  my ($vehicleid,$datatype) = @rest;

  if ( ! FunctionCall('DbHasVehicle', $username, $vehicleid) )
    {
    AE::log info => join(' ','http','-',$sessionid,$req->client_host.':'.$req->client_port,'Forbidden access',$vehicleid);
    $req->respond ( [403, 'Forbidden', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Forbidden\n"] );
    $httpd->stop_request;
    return;
    }

  my @result;
  if (!defined $datatype)
    {
    # A Request for the historical data summary
    foreach my $row (FunctionCall('DbGetHistoricalSummary', $username, $vehicleid))
      {
      my %h;
      foreach (qw(h_recordtype distinctrecs totalrecs totalsize first last))
        {
        $h{$_} = $row->{$_};
        }
      push @result, \%h;
      }
    }
  else
    {
    # A request for a specific type of historical data
    foreach my $row (FunctionCall('DbGetHistoricalRecords',$username,$vehicleid,$datatype))
      {
      my %h;
      foreach (qw(h_timestamp h_recordnumber h_data))
        {
        $h{$_} = $row->{$_};
        }
      push @result, \%h;
      }
    }

  my $json = JSON::XS->new->utf8->canonical->encode (\@result) . "\n";
  $req->respond ( [200, 'Ok', { 'Content-Type' => 'application/json', 'Access-Control-Allow-Origin' => '*' }, $json] );
  $httpd->stop_request;
  }

########################################################
# API function dispatcher

sub http_request_in_api
  {
  my ($httpd, $req) = @_;

  my $method = $req->method;
  my $path = $req->url->path;
  my @paths = $req->url->path_segments;
  my $headers = $req->headers;

  my $cookie = $headers->{'cookie'};
  my $sessionid = '-';
  if (defined $cookie)
    {
    COOKIEJAR: foreach (split /;\s+/,$cookie)
      {
      if (/^ovmsapisession=(.+)/)
        {
        $sessionid = $1;
        last COOKIEJAR;
        }
      }
    }

  if ($paths[0] eq '')
    {
    shift @paths; # Skip '' root
    shift @paths; # Skip 'api'
    my $fn = shift @paths;
    my $apicall = $http_request_api_call{uc($method) . ':' . $fn};
    if (defined $apicall)
      {
      my ($fnc,@rights) = @{$apicall};

      AE::log info => join(' ','http','-',$sessionid,$req->client_host.':'.$req->client_port,'ok',$req->method,join('/',$req->url->path_segments));

      # Try to authenticate (by cookie, or username)...
      my $username;
      my $permissions = 'none';
      if ((defined $sessionid)&&($sessionid ne '-')&&(defined $api_conns{$sessionid}))
        {
        # We have an existing session that we can use
        $username =    $api_conns{$sessionid}{'owner'};
        $permissions = $api_conns{$sessionid}{'permissions'};
        }
      else
        {
        my $u = $req->url->query_param('username');
        my $p = $req->url->query_param('password');
        if ((defined $u)&&(defined $p))
          {
          $permissions = FunctionCall('Authenticate',$u,$p);
          $username = $u if ($permissions ne '');
          }
        }

      if ((defined $username)&&($permissions ne 'none'))
        {
        if ((scalar @rights == 0) || (IsPermitted($permissions,@rights)))
          {
          &$fnc($httpd, $req, $sessionid, $username, $permissions, @paths);
          return;
          }
        else
          {
          $req->respond ( [403, 'Forbidden', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Insufficient rights\n"] );
          $httpd->stop_request;
          return;
          }
        }
      else
        {
        $req->respond ( [401, 'Unauthorized', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Authentication failed\n"] );
        $httpd->stop_request;
        return;
        }
      }
    }

  AE::log error => join(' ','http','-',$sessionid,$req->client_host.':'.$req->client_port,'noapi',$req->method,join('/',$req->url->path_segments));
  $req->respond ( [404, 'Unrecongised API call', { 'Content-Type' => 'text/plain', 'Access-Control-Allow-Origin' => '*' }, "Unrecognised API call\n"] );
  $httpd->stop_request;
  }

sub api_vehiclerecord
  {
  my ($owner,$vehicleid,$code) = @_;

  foreach my $row (FunctionCall('DbGetMessages',$owner,$vehicleid))
    {
    return $row if ($row->{'m_code'} eq $code);
    }

  return undef;
  }

1;
