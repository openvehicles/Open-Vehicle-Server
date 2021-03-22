#!/usr/bin/perl

########################################################################
# OVMS Server Protocol v2 plugin
#
# This plugin provides base support for the OVMS v2 protocol, listening
# on ports tcp/6867 (standard) and tcp/6870 (SSL/TLS).

package OVMS::Server::ApiV2;

use strict;
use warnings;
use Carp;

use AnyEvent;
use AnyEvent::Handle;
use AnyEvent::Socket;
use AnyEvent::Log;
use OVMS::Server::Core;
use OVMS::Server::Plugin;
use Socket qw(SOL_SOCKET SO_KEEPALIVE);
use IO::Handle;
use MIME::Base64;
use Protocol::WebSocket;

use Exporter qw(import);

our @EXPORT = qw();

# TCP constants

use constant SOL_TCP => 6;
use constant TCP_KEEPIDLE => 4;
use constant TCP_KEEPINTVL => 5;
use constant TCP_KEEPCNT => 6;

# API: Protocol v2

my $b64tab = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

my $me; # Reference to our singleton object
my %group_msgs;                # Current group messages (index by groupid, vkey)
my %group_subs;                # Current group subscriptions (index by groupid)
my %authfail_notified;         # Authentication failure notified (keyed by vkey)
my $timeout_app;               # Seconds after which to timeout App connections
my $timeout_car;               # Seconds after which to timeout Car connections
my $timeout_api;               # Seconds after which to timeout Api connections
my $loghistory_tim;            # Time (in seconds) to retain log history for
my $server_guard1;             # Guard object for plaintext server
my $server_guard2;             # Guard object for SSL server

use vars qw{
  };

sub new
  {
  my $class = shift;
  $class = ref($class) || $class;
  my $self = {@_};
  bless( $self, $class );

  $me = $self;

  $timeout_app       = MyConfig()->val('server','timeout_app',60*20);
  $timeout_car       = MyConfig()->val('server','timeout_car',60*16);
  $timeout_api       = MyConfig()->val('server','timeout_api',60*2);
  $loghistory_tim    = MyConfig()->val('log','history',0);

  RegisterEvent('StartRun', \&start);

  return $self;
  }

sub start
  {
  AE::log info => "- - - starting V2 server listener on port tcp/6867";
  $server_guard1 = tcp_server undef, 6867, sub
    {
    my ($fh, $host, $port) = @_;
    my $key = "$host:$port";
    $fh->blocking(0);
    my $fn = $fh->fileno();
    AE::log info => "#$fn - - new connection from $host:$port";
    my $handle; $handle = new AnyEvent::Handle(
      fh => $fh,
      on_error => \&io_error_handle,
      on_rtimeout => \&io_timeout_handle,
      keepalive => 1,
      no_delay => 1,
      rtimeout => 30);
    $handle->push_read (line => \&io_handle_welcome);

    setsockopt($fh, SOL_SOCKET, SO_KEEPALIVE, 1);
    setsockopt($fh, SOL_TCP, TCP_KEEPCNT, 9);
    setsockopt($fh, SOL_TCP, TCP_KEEPIDLE, 240);
    setsockopt($fh, SOL_TCP, TCP_KEEPINTVL, 240);

    ConnStart($fn,(
      'fh' => $fh,
      'handle' => $handle,
      'host' => $host,
      'port' => $port,
      'callback_tx' => \&callback_io_tx_handle,
      'callback_shutdown' => \&callback_io_shutdown_handle,
      'proto' => 'v2/6867'));
    };

  my $pemfile = MyConfig()->val('v2','sslcrt','conf/ovms_server.pem');
  if (-e $pemfile)
    {
    AE::log info => "- - - starting V2 SSL server listener on port tcp/6870";
    $server_guard2 = tcp_server undef, 6870, sub
      {
      my ($fh, $host, $port) = @_;
      my $key = "$host:$port";
      $fh->blocking(0);
      my $fn = $fh->fileno();
      AE::log info => "#$fn - - new TLS connection from $host:$port";
      my $handle; $handle = new AnyEvent::Handle(
        fh => $fh,
        tls      => "accept",
        tls_ctx  => { cert_file => $pemfile },
        on_error => \&io_error_handle,
        on_rtimeout => \&io_timeout_handle,
        keepalive => 1,
        no_delay => 1,
        rtimeout => 30);
      $handle->push_read (line => \&io_handle_welcome);

      setsockopt($fh, SOL_SOCKET, SO_KEEPALIVE, 1);
      setsockopt($fh, SOL_TCP, TCP_KEEPCNT, 9);
      setsockopt($fh, SOL_TCP, TCP_KEEPIDLE, 240);
      setsockopt($fh, SOL_TCP, TCP_KEEPINTVL, 240);

      ConnStart($fn,(
        'fh' => $fh,
        'handle' => $handle,
        'host' => $host,
        'port' => $port,
        'callback_tx' => \&callback_io_tx_handle,
        'callback_shutdown' => \&callback_io_shutdown_handle,
        'proto' => 'v2/6870/tls'));
      };
    };
  }

sub subkeycnt
  {
  my (%hash) = @_;
  my $cnt = 0;
  foreach my $vid (keys %hash) { $cnt += keys %{$hash{$vid}}; }
  return $cnt;
  }

my $loghistory_rec = 0;
sub log
  {
  my ($fh, $clienttype, $owner, $vehicleid, $msg, $level) = @_;

  $clienttype = "-" if !defined($clienttype);
  $vehicleid = "-" if !defined($vehicleid);
  $level = "info" if !defined($level);

  my $vkey = $owner . '/' . $vehicleid;

  AE::log $level, "#$fh $clienttype $vkey $msg";

  return if ($vehicleid eq '-');
  return if ($loghistory_tim<=0);

  FunctionCall('DbSaveHistorical',
    UTCTime(),
    '*-OVM-ServerLogs',
    $loghistory_rec++,
    $owner,
    $vehicleid,
    "#$fh $clienttype $msg",
    UTCTime(time+MyConfig()->val('log','history',0)));

  $loghistory_rec=0 if ($loghistory_rec>65535);
  }

sub io_error_handle
  {
  my ($hdl, $fatal, $msg) = @_;

  my $fn = $hdl->fh->fileno();
  my $vehicleid = ConnGetAttribute($fn,'vehicleid'); $vehicleid='-' if (!defined $vehicleid);
  my $owner = ConnGetAttribute($fn,'owner'); $owner='-' if (!defined $owner);
  my $clienttype = ConnGetAttribute($fn,'clienttype'); $clienttype='-' if (!defined $clienttype);

  if ($msg =~ /^(Broken pipe|Connection reset by peer)$/)
    { &io_terminate($fn, $owner, $vehicleid, "disconnected"); }
  else
    { &io_terminate($fn, $owner, $vehicleid, "got error: $msg"); }
  }

sub io_timeout_handle
  {
  my ($hdl) = @_;

  my $fn = $hdl->fh->fileno();
  my $vehicleid = ConnGetAttribute($fn,'vehicleid'); $vehicleid='-' if (!defined $vehicleid);
  my $owner = ConnGetAttribute($fn,'owner');
  my $vkey = $owner . '/' . $vehicleid;
  my $clienttype = ConnGetAttribute($fn,'clienttype'); $clienttype='-' if (!defined $clienttype);

  # We've got an N second receive data timeout

  # Let's see if this is the initial welcome message negotiation...
  if ($clienttype eq '-')
    {
    # OK, it has been 60 seconds since the client connected, but still no identification
    # Time to shut it down...
    &io_terminate($fn, $owner, $vehicleid, "timeout due to no initial welcome exchange");
    return;
    }

  # At this point, it is either a car or an app - let's handle the timeout
  my $now = AnyEvent->now;
  my $lastrx =ConnGetAttribute($fn,'lastrx');
  my $lasttx = ConnGetAttribute($fn,'lasttx');
  my $lastping = ConnGetAttribute($fn,'lastping');
  if ($clienttype eq 'A')
    {
    if (($lastrx+$timeout_app)<$now)
      {
      # The APP has been unresponsive for timeout_app seconds - time to disconnect it
      &io_terminate($fn, $owner, $vehicleid, "timeout due app due to inactivity");
      return;
      }
    }
  elsif ($clienttype eq 'B')
    {
    my $timeout_api  = MyConfig()->val('server','timeout_api',60*2);
    if (($lastrx+$timeout_api)<$now)
      {
      # The BATCHCLIENT has been unresponsive for timeout_api seconds - time to disconnect it
      &io_terminate($fn, $owner, $vehicleid, "timeout btc due to inactivity");
      return;
      }
    }
  elsif ($clienttype eq 'C')
    {
    if (($lastrx+$timeout_car)<$now)
      {
      # The CAR has been unresponsive for timeout_car seconds - time to disconnect it
      &io_terminate($fn, $owner, $vehicleid, "timeout car due to inactivity");
      return;
      }
    if ( (($lasttx+$timeout_car-60)<$now) && (($lastping+300)<$now) )
      {
      # We haven't sent anything to the CAR for timeout_car-60 seconds - time to ping it
      AE::log info => "#$fn $clienttype $vkey ping car due to inactivity";
      ConnTransmit($fn, 'v2', 'A', 'FA');
      ConnSetAttribute($fn,'lastping',$now);
      }
    }
  }

sub io_handle_welcome
  {
  my ($hdl, $line) = @_;

  my $fn = $hdl->fh->fileno();

  if (! ConnDefined($fn))
    {
    AE::log warn => "#$fn - - welcome line received after disconnection - ignore";
    return;
    }

  if (&welcome($fn, $line))
    {
    $hdl->push_read(line => \&io_line);
    }
  }

sub welcome
  {
  my ($fn, $line) = @_;

  AE::log debug => "#$fn - - rx welcome $line";

  ConnSetAttribute($fn,'lastrx',time);

  if ($line =~ /^MP-(\S)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(\s+(.+))?/)
    {
    #
    # CONNECTION INIT (WELCOME MESSAGE)
    #
    if ($2 eq '0')
      {
      ConnSetAttribute($fn,'protscheme',$2);
      &welcome_30($fn,$line,$1,$3,$4,uc($5),$7);
      return 1;
      }
    elsif ($2 eq '1')
      {
      ConnSetAttribute($fn,'protscheme',$2);
      &welcome_31($fn,$line,$1,$3,$4,uc($5),$7);
      return 1;
      }
    else
      {
      ConnShutdown($fn);
      ConnFinish($fn);
      AE::log debug => "#$fn - - unsupported protection scheme '$2' - aborting connection";
      return 0;
      }
    }
  elsif ($line =~ /^AP-C\s+(\S)\s+(\S+)/)
    {
    #
    # AUTO PROVISIONING
    #
    if ($1 eq '0')
      {
      ConnSetAttribute($fn,'protscheme',$1);
      &ap_30($fn,$line,$2);
      return 1;
      }
    else
      {
      ConnShutdown($fn);
      ConnFinish($fn);
      AE::log debug => "#$fn - - unsupported protection scheme '$2' - aborting connection";
      return 0;
      }
    }
  elsif (($line =~ /^GET\s+\/apiv2\/?\s+HTTP\/\S+$/)&&(ConnGetAttribute($fn,'proto') =~ /^v2/))
    {
    # A websocket connection
    my $handle = ConnGetAttribute($fn,'handle');
    my $hs = Protocol::WebSocket::Handshake::Server->new;
    my $frame = Protocol::WebSocket::Frame->new;
    ConnSetAttribute($fn,'ws_handshake',$hs);
    ConnSetAttribute($fn,'ws_frame',$frame);
    $hs->parse($line."\r\n");
    $handle->on_read(sub
      {
      my $hdl = shift;
      my $chunk = $hdl->{rbuf};
      $hdl->{rbuf} = undef;
      if (!$hs->is_done)
        {
        $hs->parse($chunk);
        if ($hs->is_done)
          {
          AE::log info => "#$fn - - connection upgraded to websocket";
          ConnSetAttribute($fn,'proto','ws/'.ConnGetAttribute($fn,'proto'));
          ConnSetAttribute($fn,'callback_tx',\&callback_io_tx_ws);
          $hdl->push_write($hs->to_string);
          return 0;
          }
        }
      $frame->append($chunk);
      while (my $message = $frame->next)
        {
        my $wsline = $message;
        if (ConnHasAttribute($fn,'owner'))
          {
          # Connection has logged on already
          &line($fn,$wsline);
          }
        else
          {
          &welcome($fn,$wsline);
          }
        }
      } );
    return 0;
    }
  else
    {
    ConnShutdown($fn);
    ConnFinish($fn);
    AE::log debug => "#$fn - - error - unrecognised message from vehicle";
    return 0;
    }
  return 0;
  }

sub io_line
  {
  my ($hdl, $line) = @_;

  my $fn = $hdl->fh->fileno();

  if (! ConnDefined($fn))
    {
    AE::log warn => "#$fn - - message line received after disconnection - ignore"; 
    return;
    }

  &line($fn, $line);
  $hdl->push_read(line => \&io_line);
  }

sub line
  {
  my ($fn, $line) = @_;

  my $vehicleid = ConnGetAttribute($fn,'vehicleid'); $vehicleid='-' if (!defined $vehicleid);
  my $owner = ConnGetAttribute($fn,'owner'); $owner=0 if (!defined $owner);
  my $vkey = $owner . '/' . $vehicleid;
  my $clienttype = ConnGetAttribute($fn,'clienttype'); $clienttype='-' if (!defined $clienttype);
  FunctionCall('DbUtilisation',$owner,$vehicleid,$clienttype,length($line)+2,0);
  AE::log debug => "#$fn $clienttype $vkey rx enc $line";
  ConnSetAttribute($fn,'lastrx',time);

  return if (!ConnHasAttribute($fn,'vehicleid'));

  my $message = $line;
  if (ConnGetAttribute($fn,'protscheme') eq '0')
    {
    my $rxc = ConnGetAttributeRef($fn,'rxcipher');
    $message = $$rxc->RC4(decode_base64($line));
    }
  elsif (ConnGetAttribute($fn,'protscheme') eq '1')
    {
    $message = 'MP-0 ' . $message;
    }

  #
  # STANDARD PROTOCOL MESSAGE
  #

  my $vrec = &FunctionCall('DbGetVehicle',ConnGetAttribute($fn,'owner'),ConnGetAttribute($fn,'vehicleid'));
  if ($message =~ /^MP-0\s(\S)(.*)/)
    {
    my ($code,$data) = ($1,$2);
    &log($fn, $clienttype, $owner, $vehicleid, "rx msg $code $data");
    &io_message($fn, $owner, ConnGetAttribute($fn,'vehicleid'), $vrec, $code, $data);
    }
  else
    {
    &io_terminate($fn, $owner, $vehicleid, "error - Unable to decode message - aborting connection");
    return;
    }
  }

sub welcome_30
  {
  my ($fn,$line,$clienttype,$clienttoken,$clientdigest,$vehicleid,$rest) = @_;

  my $vrec = &FunctionCall('DbGetVehicle',undef,$vehicleid);
  if (!defined $vrec)
    {
    ConnShutdown($fn);
    ConnFinish($fn);
    AE::log debug => "#$fn - $vehicleid error - Unknown vehicle - aborting connection";
    return;
    }

  # At this point we don't know the owner, so calculate it from the looked up vehicle record
  my $owner = $vrec->{'owner'};
  my $vkey = $owner . '/' . $vehicleid;
  ConnSetAttribute($fn,'owner',$owner);

  # Authenticate the client
  my $dclientdigest = decode_base64($clientdigest);
  my $serverhmac = Digest::HMAC->new($vrec->{'carpass'}, "Digest::MD5");
  $serverhmac->add($clienttoken);
  if ($serverhmac->digest() ne $dclientdigest)
    {
    if (($clienttype eq 'C')&&(!defined $authfail_notified{$vkey}))
      {
      $authfail_notified{$vkey}=1;
      my $host = ConnGetAttribute($fn,'host');
      FunctionCall('PushNotify', $owner, $vehicleid, 'A', "Vehicle authentication failed ($host)");
      }
    &io_terminate($fn,$owner,$vehicleid, "error - Incorrect client authentication - aborting connection");
    return;
    }
  else
    {
    if (($clienttype eq 'C')&&(defined $authfail_notified{$vkey}))
      {
      delete $authfail_notified{$vkey};
      my $host = ConnGetAttribute($fn,'host');
      FunctionCall('PushNotify', $owner, $vehicleid, 'A', "Vehicle authentication successful ($host)");
      }
    }

  # Check server permissions
  if (($clienttype eq 'S')&&($vrec->{'v_type'} ne 'SERVER'))
    {
    &io_terminate($fn,$owner,$vehicleid, "error - Can't authenticate a car as a server - aborting connection");
    return;
    }

  # Calculate a server token
  my $servertoken;
  foreach (0 .. 21)
    { $servertoken .= substr($b64tab,rand(64),1); }
  $serverhmac = Digest::HMAC->new($vrec->{'carpass'}, "Digest::MD5");
  $serverhmac->add($servertoken);
  my $serverdigest = encode_base64($serverhmac->digest(),'');

  # Calculate the shared session key
  $serverhmac = Digest::HMAC->new($vrec->{'carpass'}, "Digest::MD5");
  my $sessionkey = $servertoken . $clienttoken;
  $serverhmac->add($sessionkey);
  my $serverkey = $serverhmac->digest;
  AE::log debug => "#$fn $clienttype $vkey crypt session key $sessionkey (".unpack("H*",$serverkey).")";
  my $txcipher = Crypt::RC4::XS->new($serverkey);
  $txcipher->RC4(chr(0) x 1024);  # Prime with 1KB of zeros
  my $rxcipher = Crypt::RC4::XS->new($serverkey);
  $rxcipher->RC4(chr(0) x 1024);  # Prime with 1KB of zeros

  # Store these for later use...
  ConnSetAttributes($fn,
    ( 'serverkey' => $serverkey,
      'serverdigest' => $serverdigest,
      'servertoken' => $servertoken,
      'clientdigest' => $clientdigest,
      'clienttoken' => $clienttoken,
      'vehicleid' => $vehicleid,
      'owner' => $owner,
      'vkey' => $owner . '/' . $vehicleid,
      'txcipher' => $txcipher,
      'rxcipher' => $rxcipher,
      'clienttype' => $clienttype,
      'lastping' => time,
      'permissions' =>'*' ) );

  # Send out server welcome message
  AE::log debug => "#$fn $clienttype $vkey tx MP-S 0 $servertoken $serverdigest";
  my $towrite = "MP-S 0 $servertoken $serverdigest";
  ConnIncAttribute($fn,'tx',length($towrite));
  ConnTransmit($fn, 'v2raw', $towrite);
  # return if ($hdl->destroyed);

  # Account for it...
  FunctionCall('DbUtilisation',$owner,$vehicleid,$clienttype,length($line)+2,length($towrite));

  # Login...
  &do_login($fn,$owner,$vehicleid,$clienttype,$rest);
  }

sub ap_30
  {
  my ($fn,$line,$apkey) = @_;

  if (ConnHadAttribute($fn,'ap_already'))
    {
    AE::log note => "#$fn C - error: Already auto-provisioned on this connection";
    AE::log info => "#$fn C - tx AP-X";
    my $towrite = "AP-X";
    ConnIncAttribute($fn,'tx',length($towrite));
    ConnTransmit($fn, 'v2raw', $towrite);
    return;
    }
  ConnSetAttribute($fn,'ap_already',1);
  my $row = &FunctionCall('DbGetAutoProvision',$apkey);
  if (!defined $row)
    {
    AE::log note => "#$fn C - no auto-provision profile found for $apkey";
    AE::log info => "#$fn C - tx AP-X";
    my $towrite = "AP-X";
    ConnIncAttribute($fn,'tx',length($towrite));
    ConnTransmit($fn, 'v2raw', $towrite);
    return;
    }
  # All ok, let's send the data...
  my $towrite = "AP-S 0 ".join(' ',$row->{'ap_stoken'},$row->{'ap_sdigest'},$row->{'ap_msg'});
  AE::log info => "#$fn C - tx AP-S 0 ".join(' ',$row->{'ap_stoken'},$row->{'ap_sdigest'},$row->{'ap_msg'});
  ConnIncAttribute($fn,'tx',length($towrite));
  ConnTransmit($fn, 'v2raw', $towrite);
  }

sub welcome_31
  {
  my ($fn,$line,$clienttype,$username,$password,$vehicleid,$rest) = @_;

  my $permissions = FunctionCall('Authenticate',$username,$password);
  if ($permissions ne '')
    {
    if (! IsPermitted($permissions,'v2'))
      {
      ConnShutdown($fn);
      ConnFinish($fn);
      AE::log info => "#$fn - - error - Insufficient permission rights for 'v2' access - aborting connection";
      return;
      }
    AE::log info => "#$fn - - authenticated";
    my $orec = FunctionCall('DbGetOwner', $username);
    if (defined $orec)
      {
      AE::log info => "#$fn - - got owner";
      my $vrec;
      if ($vehicleid eq '*')
        {
        my @ovrecs = FunctionCall('DbGetOwnerCars',$username);
        $vrec = $ovrecs[0] if (scalar @ovrecs > 0);
        AE::log info => "#$fn - - got " . (scalar @ovrecs) . " cars";
        $vehicleid = $vrec->{'vehicleid'};
        }
      else
        {
        $vrec = &FunctionCall('DbGetVehicle',$username,$vehicleid);
        }
      if (defined $vrec)
        {
        AE::log info => "#$fn - - got vehicle V=$vehicleid";
        my $vkey = $username . '/' . $vehicleid;
        ConnSetAttributes($fn,
          ( 'owner' => $username,
            'vehicleid' =>  $vehicleid,
            'owner' => $username,
            'vkey' => $vkey,
            'clienttype' => $clienttype,
            'lastping' => time,
            'permissions' => $permissions ) );

        my @cars;
        foreach my $vrec (&FunctionCall('DbGetOwnerCars',$username))
          {
          push @cars, $vrec->{'vehicleid'};
          }
        AE::log debug => "#$fn $clienttype $vkey tx MP-S 1 $username $vehicleid ".join(' ',@cars);
        my $towrite = "MP-S 1 $username $vehicleid ".join(' ',@cars);
        ConnIncAttribute($fn,'tx',length($towrite));
        ConnTransmit($fn, 'v2raw', $towrite);
        FunctionCall('DbUtilisation',$username,$vehicleid,$clienttype,length($line)+2,length($towrite));
        &do_login($fn,$username,$vehicleid,$clienttype,$rest);
        return;
        }
      }
    }

  ConnShutdown($fn);
  ConnFinish($fn);
  AE::log info => "#$fn - - error - Incorrect client authentication - aborting connection";
  return;
  }

sub do_login
  {
  my ($fn,$owner,$vehicleid,$clienttype,$rest) = @_;

  my $vkey = $owner . '/' . $vehicleid;

  &log($fn, $clienttype, $owner, $vehicleid, "got proto #" . ConnGetAttribute($fn,'protscheme') . "/$clienttype login");

  if ($clienttype eq 'A')      # An APP login
    {
    AppConnect($owner,$vehicleid,$fn);
    # Notify any listening cars
    my $cfn = CarConnection($owner,$vehicleid);
    if (defined $cfn)
      {
      ConnTransmit($cfn, 'v2', 'Z', AppConnectionCount($owner,$vehicleid));
      }
    # And notify the app itself
    ConnTransmit($fn, 'v2', 'Z', (defined CarConnection($owner,$vehicleid))?"1":"0");
    # Update the app with current stored messages
    my $vrec = &FunctionCall('DbGetVehicle',$owner,$vehicleid);
    my $v_ptoken = $vrec->{'v_ptoken'};
    foreach my $row (FunctionCall('DbGetMessages',$owner,$vehicleid))
      {
      if ($row->{'m_paranoid'})
        {
        if ($v_ptoken ne '')
          {
          ConnTransmit($fn, 'v2', 'E', 'T'.$v_ptoken);
          $v_ptoken = ''; # Make sure it only gets sent once
          }
        ConnTransmit($fn, 'v2', 'E', 'M'.$row->{'m_code'}.$row->{'m_msg'});
        }
      else
        {
        ConnTransmit($fn, 'v2', $row->{'m_code'},$row->{'m_msg'});
        }
      }
    ConnTransmit($fn, 'v2', 'T', $vrec->{'v_lastupdatesecs'});
    }

  elsif ($clienttype eq 'B')      # A BATCHCLIENT login
    {
    BatchConnect($owner,$vehicleid,$fn);
    # Send peer status
    ConnTransmit($fn, 'v2', 'Z', (defined CarConnection($owner,$vehicleid))?"1":"0");
    # Send current stored messages
    my $vrec = &FunctionCall('DbGetVehicle',$owner,$vehicleid);
    my $v_ptoken = $vrec->{'v_ptoken'};
    foreach my $row (FunctionCall('DbGetMessages',$owner,$vehicleid))
      {
      if ($row->{'m_paranoid'})
        {
        if ($v_ptoken ne '')
          {
          ConnTransmit($fn, 'v2', 'E', 'T'.$v_ptoken);
          $v_ptoken = ''; # Make sure it only gets sent once
          }
        ConnTransmit($fn, 'v2', 'E', 'M'.$row->{'m_code'}.$row->{'m_msg'});
        }
      else
        {
        ConnTransmit($fn, 'v2', $row->{'m_code'},$row->{'m_msg'});
        }
      }
    ConnTransmit($fn, 'v2', 'T', $vrec->{'v_lastupdatesecs'});
    }

  elsif ($clienttype eq 'C')      # A CAR login
    {
    my $efn = CarConnection($owner,$vehicleid);
    if (defined $efn)
      {
      # Car is already logged in - terminate it
      &io_terminate($efn,$owner,$vehicleid, "error - duplicate car login - clearing first connection");
      }
    CarConnect($owner,$vehicleid,$fn);
    # Notify any listening apps & batch clients
    ClientsTransmit($owner, $vehicleid, 'v2', 'Z', '1');
    # And notify the car itself about listening apps
    ConnTransmit($fn, 'v2', 'Z', AppConnectionCount($owner,$vehicleid));
    }
  }

sub io_terminate
  {
  my ($fn, $owner, $vehicleid, $msg) = @_;

  my $vkey = $owner . '/' . $vehicleid;

  #AE::log error => $msg if (defined $msg);
  &log($fn, ConnGetAttribute($fn,'clienttype'), $owner, $vehicleid, $msg, "error") if (defined $msg);

  if ((defined $vehicleid)&&(ConnHasAttribute($fn,'clienttype')))
    {
    if (ConnGetAttribute($fn,'clienttype') eq 'C')
      {
      CarDisconnect($owner,$vehicleid,$fn);
      # Notify any listening apps & batch clients
      ClientsTransmit($owner, $vehicleid, 'v2', 'Z', '0');
      # Cleanup group messages
      if (ConnHasAttribute($fn,'cargroups'))
        {
        foreach (keys %{ConnGetAttribute($fn,'cargroups')})
          {
          delete $group_msgs{$_}{$vkey};
          }
        }
      }
    elsif (ConnGetAttribute($fn,'clienttype') eq 'A')
      {
      &io_cleanup_cmdqueue($fn,"A",$owner,$vehicleid);
      AppDisconnect($owner,$vehicleid,$fn);
      # Notify car about new app count
      CarTransmit($owner, $vehicleid, 'v2', 'Z', AppConnectionCount($owner,$vehicleid));
      # Cleanup group messages
      if (ConnHasAttribute($fn,'appgroups'))
        {
        foreach (keys %{ConnGetAttribute($fn,'appgroups')})
          {
          delete $group_subs{$_}{$fn};
          }
        }
      }
    elsif (ConnGetAttribute($fn,'clienttype') eq 'B')
      {
      &io_cleanup_cmdqueue($fn,"B",$owner,$vehicleid);
      BatchDisconnect($owner,$vehicleid,$fn);
      }
    }

  if (defined $fn)
    {
    ConnShutdown($fn);
    ConnFinish($fn);
    }

  return;
  }

sub io_cleanup_cmdqueue
  {
  my ($fn,$clienttype,$owner,$vehicleid) = @_;

  my $vkey = $owner . '/' . $vehicleid;

  my $cfn = CarConnection($owner,$vehicleid);
  my $changed = 0;
  if ((defined $cfn) &&
      (ConnDefined($cfn)) &&
      (ConnHasAttribute($cfn,'cmdqueue')) &&
      (scalar @{ConnGetAttribute($cfn,'cmdqueue')} > 0))
    {
    foreach my $fd (@{ConnGetAttribute($cfn,'cmdqueue')})
      {
      if ($fd eq $fn)
        { $fd=0; $changed=1; }
      }
    }
  if ($changed)
    {
    AE::log info => "#$fn $clienttype $vkey cmd cleanup of #$fn for $vehicleid (queue now ".join(',',@{ConnGetAttribute($cfn,'cmdqueue')}).")";
    }
  }

sub callback_io_tx_handle
  {
  my ($fn, $format, @data) = @_;

  my $handle = ConnGetAttribute($fn,'handle');
  return if ($handle->destroyed);

  if ($format eq 'v2raw')
    {
    # Simple raw transmission...
    $handle->push_write(join('',@data)."\r\n");
    return;
    }

  return if ($format ne 'v2');

  my ($code,$message) = @data;

  my $vid = ConnGetAttribute($fn,'vehicleid');
  my $owner = ConnGetAttribute($fn,'owner');
  my $vkey = $owner . '/' . $vid;
  my $clienttype = ConnGetAttribute($fn,'clienttype'); $clienttype='-' if (!defined $clienttype);

  my $encoded;
  if (ConnGetAttribute($fn,'protscheme') eq '0')
    {
    my $txc = ConnGetAttributeRef($fn,'txcipher');
    $encoded = encode_base64($$txc->RC4("MP-0 $code$message"),'');
    }
  else
    {
    $encoded = "$code$message";
    }

  AE::log debug => "#$fn $clienttype $vkey tx enc $encoded";
  AE::log info => "#$fn $clienttype $vkey tx msg $code $message";
  FunctionCall('DbUtilisation',$owner,$vid,$clienttype,0,length($encoded)+2);
  $handle->push_write($encoded."\r\n");
  ConnSetAttribute($fn,'lasttx',time);
  }

sub callback_io_shutdown_handle
  {
  my ($fn) = @_;

  if (ConnHasAttribute($fn, 'handle'))
    {
    my $hdl = ConnGetAttribute($fn, 'handle');
    $hdl->destroy;
    }
  }

sub callback_io_tx_ws
  {
  my ($fn, $format, @data) = @_;

  my $handle = ConnGetAttribute($fn,'handle');
  return if ($handle->destroyed);

  my $frame = ConnGetAttributeRef($fn,'ws_frame');

  if ($format eq 'v2raw')
    {
    # Simple raw transmission...
    $handle->push_write($$frame->new(join('',@data))->to_bytes);
    return;
    }

  return if ($format ne 'v2');

  my ($code,$message) = @data;

  my $vid = ConnGetAttribute($fn,'vehicleid');
  my $owner = ConnGetAttribute($fn,'owner');
  my $vkey = $owner . '/' . $vid;
  my $clienttype = ConnGetAttribute($fn,'clienttype'); $clienttype='-' if (!defined $clienttype);

  my $encoded;
  if (ConnGetAttribute($fn,'protscheme') eq '0')
    {
    my $txc = ConnGetAttributeRef($fn,'txcipher');
    $encoded = encode_base64($$txc->RC4("MP-0 $code$message"),'');
    }
  else
    {
    $encoded = "$code$message";
    }

  AE::log debug => "#$fn $clienttype $vkey tx enc $encoded";
  AE::log info => "#$fn $clienttype $vkey tx msg $code $message";
  FunctionCall('DbUtilisation',$owner,$vid,$clienttype,0,length($encoded)+2);
  $handle->push_write($$frame->new($encoded)->to_bytes);
  ConnSetAttribute($fn,'lasttx',time);
  }

# Message handlers
sub io_message
  {
  my ($fn,$owner,$vehicleid,$vrec,$code,$data) = @_;

  my $vkey = $owner . '/' . $vehicleid;

  my $clienttype = ConnGetAttribute($fn,'clienttype'); $clienttype='-' if (!defined $clienttype);

  # Handle system-level messages first
  if ($code eq 'A') ## PING
    {
    AE::log info => "#$fn $clienttype $vkey msg ping from $vehicleid";
    ConnTransmit($fn, 'v2', 'a', '');
    return;
    }
  elsif ($code eq 'a') ## PING ACK
    {
    AE::log info => "#$fn $clienttype $vkey msg pingack from $vehicleid";
    return;
    }
  elsif ($code eq 'P') ## PUSH NOTIFICATION
    {
    AE::log info => "#$fn $clienttype $vkey msg push notification '$data' => $vehicleid";
    # Send it to any listening apps
    ClientsTransmit($owner, $vehicleid, 'v2', $code, $data);
    # And also send via the mobile networks
    if ($data =~ /^(.)(.+)/)
      {
      my ($alerttype, $alertmsg) = ($1,$2);
      FunctionCall('PushNotify', $owner, $vehicleid, $alerttype, $alertmsg);
      }
    return;
    }
  elsif ($code eq 'p') ## PUSH SUBSCRIPTION
    {
    my ($appid,$pushtype,$pushkeytype,$vkeys) = split /,/,$data,4;
    $pushkeytype='production' if ($pushtype eq 'apns');
    ConnSetAttribute($fn,'appid',$appid);
    if ((defined $vkeys)&&($vkeys ne '')&&($vkeys =~ /^([^,]+),(.+),([^,]+)$/))
      {
      my $vk_vehicleid = $1;
      my $vk_netpass = $2;
      my $vk_pushkeyvalue = $3;

      my $vk_rec = &FunctionCall('DbGetVehicle',$owner,$vk_vehicleid);
      if ((defined $vk_rec)&&($vk_rec->{'carpass'} eq $vk_netpass))
        {
        AE::log info => "#$fn $clienttype $vkey msg push subscription $vk_vehicleid:$pushtype/$pushkeytype => $vk_pushkeyvalue";
        FunctionCall('DbRegisterPushNotify',$owner,$vk_vehicleid,$appid,$pushtype,$pushkeytype,$vk_pushkeyvalue);
        }
      }
    return;
    }

  # The remaining messages are standard

  # Handle paranoid messages
  my $m_paranoid=0;
  my $m_code=$code;
  my $m_data=$data;
  if ($code eq 'E')
    {
    my ($paranoidmsg,$paranoidcode,$paranoiddata,$paranoidtoken)=($1,$3,$4,$2) if ($data =~ /^(.)((.)(.+))$/);
    if ($paranoidmsg eq 'T')
      {
      # The paranoid token is being set
      ConnSetAttribute($fn,'ptoken',$paranoidtoken);
      ClientsTransmit($owner, $vehicleid, 'v2', $code, $data); # Send it on to connected apps
      if ($vrec->{'v_ptoken'} ne $paranoidtoken)
        {
        # Invalidate any stored paranoid messages for this vehicle
        FunctionCall('DbInvalidateParanoidMessages',$owner,$vehicleid,$paranoidtoken);
        }
      AE::log info => "#$fn $clienttype $vkey paranoid token set '$paranoidtoken'";
      return;
      }
    elsif ($paranoidmsg eq 'M')
      {
      # A paranoid message is being sent
      $m_paranoid=1;
      $m_code=$paranoidcode;
      $m_data=$paranoiddata;
      }
    else
      {
      # Unknown paranoid msg type
      AE::log error => "#$fn $clienttype $vkey unknown paranoid message type '$paranoidmsg'";
      return;
      }
    }

  # Check for App<->Server<->Car command and response messages...
  if ($m_code eq 'C')
    {
    if (($clienttype ne 'A')&&($clienttype ne 'B'))
      {
      AE::log error => "#$fn $clienttype $vkey msg invalid 'C' message from non-App/Batchclient";
      return;
      }
    if (($m_code eq $code)&&($data =~ /^(\d+)(,(.+))?$/)&&($1 == 30))
      {
      # Special case of an app requesting (non-paranoid) the GPRS data
      my $k = 0;
      my @rows = FunctionCall('DbGetHistoricalDaily',$owner,$vehicleid,'*-OVM-Utilisation',90);
      foreach my $row (@rows)
        {
        $k++;
        ConnTransmit($fn, 'v2', 'c', sprintf('30,0,%d,%d,%s,%s',$k,(scalar @rows),
               $row->{'u_date'},$row->{'data'}));
        }
      if ($k == 0)
        {
        ConnTransmit($fn, 'v2', 'c', '30,1,No GPRS utilisation data available');
        }
      return;
      }
    elsif (($m_code eq $code)&&($data =~ /^(\d+)(,(.+))?$/)&&($1 == 31))
      {
      # Special case of an app requesting (non-paranoid) the historical data summary
      my ($h_since) = $3;
      $h_since='0000-00-00' if (!defined $h_since);
      my @rows = FunctionCall('DbGetHistoricalSummary',$owner,$vehicleid,$h_since);
      my $k = 0;
      foreach my $row (@rows)
        {
        $k++;
        ConnTransmit($fn, 'v2', 'c', sprintf('31,0,%d,%d,%s,%d,%d,%d,%s,%s',$k,(scalar @rows),
          $row->{'h_recordtype'},
          $row->{'distinctrecs'},
          $row->{'totalrecs'},
          $row->{'totalsize'},
          $row->{'first'},
          $row->{'last'}));
        }
      if ($k == 0)
        {
        ConnTransmit($fn, 'v2', 'c', '31,1,No historical data available');
        }
      return;
      }
    elsif (($m_code eq $code)&&($data =~ /^(\d+)(,(.+))?$/)&&($1 == 32))
      {
      # Special case of an app requesting (non-paranoid) the GPRS data
      my ($h_recordtype,$h_since) = split /,/,$3,2;
      $h_since='0000-00-00' if (!defined $h_since);
      my @rows = FunctionCall('DbGetHistoricalRecords', $owner, $vehicleid, $h_recordtype, $h_since);
      my $k = 0;
      foreach my $row (@rows)
        {
        $k++;
        ConnTransmit($fn, 'v2', 'c', sprintf('32,0,%d,%d,%s,%s,%d,%s',$k,(scalar @rows),
          $row->{'h_recordtype'}, $row->{'h_timestamp'}, $row->{'h_recordnumber'}, $row->{'h_data'}));
        }
      if ($k == 0)
        {
        ConnTransmit($fn, 'v2', 'c', '32,1,No historical data available');
        }
      return;
      }
    my $cfn = CarConnection($owner,$vehicleid);
    if (defined $cfn)
      {
      # Let's record the FN of the app/batch sending this command
      my $cc = ConnGetAttributeRef($cfn,'cmdqueue');
      push @{$$cc},$fn;
      AE::log info => "#$fn $clienttype $vkey cmd req for $vehicleid (queue now ".join(',',@{ConnGetAttribute($cfn,'cmdqueue')}).")";
      }
    CarTransmit($owner, $vehicleid, 'v2', $code, $data); # Send it on to the car
    return;
    }
  elsif ($m_code eq 'c')
    {
    if ($clienttype ne 'C')
      {
      AE::log error => "#$fn $clienttype $vkey msg invalid 'c' message from non-Car";
      return;
      }
    # Forward to apps and batch clients
    if (scalar @{ConnGetAttribute($fn,'cmdqueue')} > 0)
      {
      # We have a specific client to send the response to
      my $cfn;
      # Nasty hacky code to determine multi-line responses for command functions 1 and 3
      my ($func,$result,$now,$max,$rest) = split /,/,$data,5;
      my $cc = ConnGetAttributeRef($fn,'cmdqueue');
      if ((($func == 1)||($func == 3)) &&
          (($result != 0)||($now < ($max-1))))
        {
        $cfn = @{$$cc}[0];
        }
      $cfn = shift @{$$cc} if (!defined $cfn);
      if ($cfn == 0)
        {
        # Client has since disconnected, so ignore it.
        AE::log info => "#$fn $clienttype $vkey cmd rsp discard for $vehicleid (queue now ".join(',',@{ConnGetAttribute($fn,'cmdqueue')}).")";
        }
      else
        {
        # Send to this one specific client
        AE::log info => "#$fn $clienttype $vkey cmd rsp to #$cfn for $vehicleid (queue now ".join(',',@{ConnGetAttribute($fn,'cmdqueue')}).")";
        ConnTransmit($cfn, 'v2', $code, $data);
        }
      }
    else
      {
      # Send it to all clients...
      ClientsTransmit($owner, $vehicleid, 'v2', $code, $data);
      }
    return;
    }
  elsif ($m_code eq 'g')
    {
    # A group update message
    my ($groupid,$groupmsg) = split /,/,$data,2;
    $groupid = uc($groupid);
    if ($clienttype eq 'C')
      {
      AE::log info => "#$fn $clienttype $vkey msg group update $groupid $groupmsg";
      # Store the update
      my $cg = ConnGetAttributeRef($fn,'cargroups');
      $$cg->{$groupid} = 1;
      $group_msgs{$groupid}{$vkey} = $groupmsg;
      # Notify all the apps
      foreach(keys %{$group_subs{$groupid}})
        {
        my $afn = $_;
        ConnTransmit($afn, 'v2', $m_code, join(',',$vehicleid,$groupid,$groupmsg));
        }
      }
    return;
    }
  elsif ($m_code eq 'G')
    {
    # A group subscription message
    my ($groupid,$groupmsg) = split /,/,$data,2;
    $groupid = uc($groupid);
    if ($clienttype eq 'A')
      {
      AE::log info => "#$fn $clienttype $vkey msg group subscribe $groupid";
      my $ag = ConnGetAttributeRef($fn,'appgroups');
      $$ag->{$groupid} = 1;
      $group_subs{$groupid}{$fn} = $fn;
      }
    # Send all outstanding group messages...
    foreach (keys %{$group_msgs{$groupid}})
      {
      my $gvkey = $_;
      my $gvehicleid = $1 if ($gvkey =~ /^.+\/(.+)$/);
      my $msg = $group_msgs{$groupid}{$gvkey};
      ConnTransmit($fn, 'v2', 'g', join(',',$gvehicleid,$groupid,$msg));
      }
    return;
    }
  elsif ($m_code eq 'H')
    {
    if ($clienttype ne 'C')
      {
      AE::log error => "#$fn $clienttype $vkey msg invalid 'H' message from non-Car";
      return;
      }
    my ($h_recordtype,$h_recordnumber,$h_lifetime,$h_data) = split /,/,$data,4;
    if (!defined $h_data)
      {
      AE::log error => "#$fn $clienttype $vkey msg invalid 'H' message ignored";
      }
    else
      {
      FunctionCall('DbSaveHistorical',UTCTime(),$h_recordtype,$h_recordnumber,$owner,$vehicleid,$h_data,UTCTime(time+$h_lifetime));
      }
    return;
    }
  elsif ($m_code eq 'h')
    {
    if ($clienttype ne 'C')
      {
      AE::log error => "#$fn $clienttype $vkey msg invalid 'h' message from non-Car";
      return;
      }
    my ($h_ackcode,$h_timediff,$h_recordtype,$h_recordnumber,$h_lifetime,$h_data) = split /,/,$data,6;
    if (!defined $h_data)
      {
      AE::log error => "#$fn $clienttype $vkey msg invalid 'h' message ignored";
      }
    else
      {
      FunctionCall('DbSaveHistorical',UTCTime(time+$h_timediff),$h_recordtype,$h_recordnumber,$owner,$vehicleid,$h_data,UTCTime(time+($h_lifetime-$h_timediff)));
      }
    ConnTransmit($fn, 'v2', 'h', $h_ackcode);
    return;
    }

  if ($clienttype eq 'C')
    {
    # Kludge: fix to 1.2.0 bug with S messages in performance mode
    if (($code eq 'S')&&($m_paranoid == 0)&&($data =~ /,performance,,/))
      {
      $data =~ s/,performance,,/,performance,/;
      $m_data =~ s/,performance,,/,performance,/;
      }
    # Let's store the data in the database...
    my $ptoken = ConnGetAttribute($fn,'ptoken'); $ptoken="" if (!defined $ptoken);
    FunctionCall('DbSaveCarMessage', $owner, $vehicleid, $m_code, 1, UTCTime(), $m_paranoid, $ptoken, $m_data);
    if ($loghistory_tim > 0)
      {
      FunctionCall('DbSaveHistorical',UTCTime(),$m_code,0,$owner,$vehicleid,$m_data,UTCTime(time+$loghistory_tim));
      }
    # And send it on to the apps...
    AE::log debug => "#$fn $clienttype $vkey msg handle $m_code $m_data";
    ClientsTransmit($owner, $vehicleid, 'v2', $code, $data);
    if ($m_code eq "F")
      {
      # Let's follow up with server version...
      ClientsTransmit($owner, $vehicleid, 'v2', 'f', GetVersion());
      }
    ClientsTransmit($owner, $vehicleid, 'v2', 'T', 0);
    }
  elsif ($clienttype eq 'A')
    {
    # Send it on to the car...
    CarTransmit($owner, $vehicleid, 'v2', $code, $data);
    }
  }

1;
