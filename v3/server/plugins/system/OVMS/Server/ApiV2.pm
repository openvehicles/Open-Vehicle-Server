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
use AnyEvent::Socket;
use AnyEvent::Log;
use OVMS::Server::Core;
use OVMS::Server::Plugin;
use Socket qw(SOL_SOCKET SO_KEEPALIVE);
use IO::Handle;
use MIME::Base64;

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
my %conns;                     # Connection informaton (keyed by fd#)
my %car_conns;                 # Car connections (vkey -> fd#)
my %app_conns;                 # App connections (vkey{$fd#})
my %btc_conns;                 # Batch connections (vkey{$fd#})
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

  RegisterFunction('CarConnectionCount', \&car_connection_count);
  RegisterFunction('AppConnectionCount', \&app_connection_count);
  RegisterFunction('BtcConnectionCount', \&btc_connection_count);
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
    my $handle; $handle = new AnyEvent::Handle(fh => $fh, on_error => \&io_error, on_rtimeout => \&io_timeout, keepalive => 1, no_delay => 1, rtimeout => 30);
    $handle->push_read (line => \&io_line_welcome);

    setsockopt($fh, SOL_SOCKET, SO_KEEPALIVE, 1);
    setsockopt($fh, SOL_TCP, TCP_KEEPCNT, 9);
    setsockopt($fh, SOL_TCP, TCP_KEEPIDLE, 240);
    setsockopt($fh, SOL_TCP, TCP_KEEPINTVL, 240);

    $conns{$fn}{'fh'} = $fh;
    $conns{$fn}{'handle'} = $handle;
    $conns{$fn}{'host'} = $host;
    $conns{$fn}{'port'} = $port;
    $conns{$fn}{'proto'} = 'v2/6867';
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
        on_error => \&io_error,
        on_rtimeout => \&io_timeout,
        keepalive => 1,
        no_delay => 1,
        rtimeout => 30);
      $handle->push_read (line => \&io_line_welcome);

      setsockopt($fh, SOL_SOCKET, SO_KEEPALIVE, 1);
      setsockopt($fh, SOL_TCP, TCP_KEEPCNT, 9);
      setsockopt($fh, SOL_TCP, TCP_KEEPIDLE, 240);
      setsockopt($fh, SOL_TCP, TCP_KEEPINTVL, 240);

      $conns{$fn}{'fh'} = $fh;
      $conns{$fn}{'handle'} = $handle;
      $conns{$fn}{'host'} = $host;
      $conns{$fn}{'port'} = $port;
      $conns{$fn}{'proto'} = 'v2/6870/ssl';
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

sub car_connection_count
  {
  my ($owner, $vehicleid) = @_;

  my $vkey = $owner . '/' . $vehicleid;

  return (defined $car_conns{$vkey})?1:0;
  }

sub app_connection_count
  {
  my ($owner, $vehicleid) = @_;

  my $vkey = $owner . '/' . $vehicleid;

  return ((defined $app_conns{$vkey})&&(scalar keys %{$app_conns{$vkey}}));
  }

sub btc_connection_count
  {
  my ($owner, $vehicleid) = @_;

  my $vkey = $owner . '/' . $vehicleid;

  return ((defined $btc_conns{$vkey})&&(scalar keys %{$btc_conns{$vkey}}));
  }

sub io_error
  {
  my ($hdl, $fatal, $msg) = @_;

  my $fn = $hdl->fh->fileno();
  my $vehicleid = $conns{$fn}{'vehicleid'}; $vehicleid='-' if (!defined $vehicleid);
  my $owner = $conns{$fn}{'owner'}; $owner='-' if (!defined $owner);
  my $clienttype = $conns{$fn}{'clienttype'}; $clienttype='-' if (!defined $clienttype);

  if ($msg =~ /^(Broken pipe|Connection reset by peer)$/)
    { &io_terminate($fn, $hdl, $owner, $vehicleid, "disconnected"); }
  else
    { &io_terminate($fn, $hdl, $owner, $vehicleid, "got error: $msg"); }
  }

sub io_timeout
  {
  my ($hdl) = @_;

  my $fn = $hdl->fh->fileno();
  my $vehicleid = $conns{$fn}{'vehicleid'}; $vehicleid='-' if (!defined $vehicleid);
  my $owner = $conns{$fn}{'owner'};
  my $vkey = $owner . '/' . $vehicleid;
  my $clienttype = $conns{$fn}{'clienttype'}; $clienttype='-' if (!defined $clienttype);

  # We've got an N second receive data timeout

  # Let's see if this is the initial welcome message negotiation...
  if ($clienttype eq '-')
    {
    # OK, it has been 60 seconds since the client connected, but still no identification
    # Time to shut it down...
    &io_terminate($fn, $hdl, $owner, $vehicleid, "timeout due to no initial welcome exchange");
    return;
    }

  # At this point, it is either a car or an app - let's handle the timeout
  my $now = AnyEvent->now;
  my $lastrx = $conns{$fn}{'lastrx'};
  my $lasttx = $conns{$fn}{'lasttx'};
  my $lastping = $conns{$fn}{'lastping'};
  if ($clienttype eq 'A')
    {
    if (($lastrx+$timeout_app)<$now)
      {
      # The APP has been unresponsive for timeout_app seconds - time to disconnect it
      &io_terminate($fn, $hdl, $$owner, $vehicleid, "timeout due app due to inactivity");
      return;
      }
    }
  elsif ($clienttype eq 'B')
    {
    my $timeout_api  = MyConfig()->val('server','timeout_api',60*2);
    if (($lastrx+$timeout_api)<$now)
      {
      # The BATCHCLIENT has been unresponsive for timeout_api seconds - time to disconnect it
      &io_terminate($fn, $hdl, $owner, $vehicleid, "timeout btc due to inactivity");
      return;
      }
    }
  elsif ($clienttype eq 'C')
    {
    if (($lastrx+$timeout_car)<$now)
      {
      # The CAR has been unresponsive for timeout_car seconds - time to disconnect it
      &io_terminate($fn, $hdl, $owner, $vehicleid, "timeout car due to inactivity");
      return;
      }
    if ( (($lasttx+$timeout_car-60)<$now) && (($lastping+300)<$now) )
      {
      # We haven't sent anything to the CAR for timeout_car-60 seconds - time to ping it
      AE::log info => "#$fn $clienttype $vkey ping car due to inactivity";
      &io_tx($fn, $conns{$fn}{'handle'}, 'A', 'FA');
      $conns{$fn}{'lastping'} = $now;
      }
    }
  }

sub io_line_welcome
  {
  my ($hdl, $line) = @_;

  my $fn = $hdl->fh->fileno();

  AE::log debug => "#$fn - - rx welcome $line";

  $hdl->push_read(line => \&io_line);
  $conns{$fn}{'lastrx'} = time;

  if ($line =~ /^MP-(\S)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(\s+(.+))?/)
    {
    #
    # CONNECTION INIT (WELCOME MESSAGE)
    #
    if ($2 eq '0')
      {
      $conns{$fn}{'protscheme'} = $2;
      &io_line_welcome_30($fn,$hdl,$line,$1,$3,$4,uc($5),$7);
      }
    elsif ($2 eq '1')
      {
      $conns{$fn}{'protscheme'} = $2;
      &io_line_welcome_31($fn,$hdl,$line,$1,$3,$4,uc($5),$7);
      }
    else
      {
      $hdl->destroy;
      delete $conns{$fn};
      AE::log debug => "#$fn - - unsupported protection scheme '$2' - aborting connection";
      return;
      }
    }
  elsif ($line =~ /^AP-C\s+(\S)\s+(\S+)/)
    {
    #
    # AUTO PROVISIONING
    #
    if ($1 eq '0')
      {
      $conns{$fn}{'protscheme'} = $1;
      &io_line_ap_30($fn,$hdl,$line,$2);
      }
    else
      {
      $hdl->destroy;
      delete $conns{$fn};
      AE::log debug => "#$fn - - unsupported protection scheme '$2' - aborting connection";
      return;
      }
    }
  else
    {
    $hdl->destroy;
    delete $conns{$fn};
    AE::log debug => "#$fn - - error - unrecognised message from vehicle";
    return;
    }
  }

sub io_line
  {
  my ($hdl, $line) = @_;

  my $fn = $hdl->fh->fileno();
  my $vehicleid = $conns{$fn}{'vehicleid'}; $vehicleid='-' if (!defined $vehicleid);
  my $owner = $conns{$fn}{'owner'}; $owner=0 if (!defined $owner);
  my $vkey = $owner . '/' . $vehicleid;
  my $clienttype = $conns{$fn}{'clienttype'}; $clienttype='-' if (!defined $clienttype);
  FunctionCall('DbUtilisation',$owner,$vehicleid,$clienttype,length($line)+2,0);
  AE::log debug => "#$fn $clienttype $vkey rx enc $line";
  $hdl->push_read(line => \&io_line);
  $conns{$fn}{'lastrx'} = time;

  return if (!defined $conns{$fn}{'vehicleid'});

  my $message;
  if ($conns{$fn}{'protscheme'} eq '0')
    {
    $message = $conns{$fn}{'rxcipher'}->RC4(decode_base64($line));
    }

  #
  # STANDARD PROTOCOL MESSAGE
  #

  my $vrec = &FunctionCall('DbGetVehicle',$conns{$fn}{'owner'},$conns{$fn}{'vehicleid'});
  if ($message =~ /^MP-0\s(\S)(.*)/)
    {
    my ($code,$data) = ($1,$2);
    &log($fn, $clienttype, $owner, $vehicleid, "rx msg $code $data");
    &io_message($fn, $hdl, $owner, $conns{$fn}{'vehicleid'}, $vrec, $code, $data);
    }
  else
    {
    &io_terminate($fn, $hdl, $owner, $vehicleid, "error - Unable to decode message - aborting connection");
    return;
    }
  }

sub io_line_welcome_30
  {
  my ($fn,$hdl,$line,$clienttype,$clienttoken,$clientdigest,$vehicleid,$rest) = @_;

  my $vrec = &FunctionCall('DbGetVehicle',undef,$vehicleid);
  if (!defined $vrec)
    {
    $hdl->destroy;
    delete $conns{$fn};
    AE::log debug => "#$fn - $vehicleid error - Unknown vehicle - aborting connection";
    return;
    }

  # At this point we don't know the owner, so calculate it from the looked up vehicle record
  my $owner = $vrec->{'owner'};
  my $vkey = $owner . '/' . $vehicleid;
  $conns{$fn}{'owner'} = $owner;

  # Authenticate the client
  my $dclientdigest = decode_base64($clientdigest);
  my $serverhmac = Digest::HMAC->new($vrec->{'carpass'}, "Digest::MD5");
  $serverhmac->add($clienttoken);
  if ($serverhmac->digest() ne $dclientdigest)
    {
    if (($clienttype eq 'C')&&(!defined $authfail_notified{$vkey}))
      {
      $authfail_notified{$vkey}=1;
      my $host = $conns{$fn}{'host'};
      FunctionCall('PushNotify', $owner, $vehicleid, 'A', "Vehicle authentication failed ($host)");
      }
    &io_terminate($fn,$hdl,$owner,$vehicleid, "error - Incorrect client authentication - aborting connection");
    return;
    }
  else
    {
    if (($clienttype eq 'C')&&(defined $authfail_notified{$vkey}))
      {
      delete $authfail_notified{$vkey};
      my $host = $conns{$fn}{'host'};
      FunctionCall('PushNotify', $owner, $vehicleid, 'A', "Vehicle authentication successful ($host)");
      }
    }

  # Check server permissions
  if (($clienttype eq 'S')&&($vrec->{'v_type'} ne 'SERVER'))
    {
    &io_terminate($fn,$hdl,$owner,$vehicleid, "error - Can't authenticate a car as a server - aborting connection");
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
  $conns{$fn}{'serverkey'} = $serverkey;
  $conns{$fn}{'serverdigest'} = $serverdigest;
  $conns{$fn}{'servertoken'} = $servertoken;
  $conns{$fn}{'clientdigest'} = $clientdigest;
  $conns{$fn}{'clienttoken'} = $clienttoken;
  $conns{$fn}{'vehicleid'} = $vehicleid;
  $conns{$fn}{'owner'} = $owner;
  $conns{$fn}{'vkey'} = $owner . '/' . $vehicleid;
  $conns{$fn}{'txcipher'} = $txcipher;
  $conns{$fn}{'rxcipher'} = $rxcipher;
  $conns{$fn}{'clienttype'} = $clienttype;
  $conns{$fn}{'lastping'} = time;
  $conns{$fn}{'permissions'} = '*';

  # Send out server welcome message
  AE::log debug => "#$fn $clienttype $vkey tx MP-S 0 $servertoken $serverdigest";
  my $towrite = "MP-S 0 $servertoken $serverdigest\r\n";
  $conns{$fn}{'tx'} += length($towrite);
  $hdl->push_write($towrite);
  return if ($hdl->destroyed);

  # Account for it...
  FunctionCall('DbUtilisation',$owner,$vehicleid,$clienttype,length($line)+2,length($towrite));

  # Login...
  &io_login($fn,$hdl,$owner,$vehicleid,$clienttype,$rest);
  }

sub io_line_ap_30
  {
  my ($fn,$hdl,$line,$apkey) = @_;

  if (defined $conns{$fn}{'ap_already'})
    {
    AE::log note => "#$fn C - error: Already auto-provisioned on this connection";
    AE::log info => "#$fn C - tx AP-X";
    my $towrite = "AP-X\r\n";
    $conns{$fn}{'tx'} += length($towrite);
    $hdl->push_write($towrite);
    return;
    }
  $conns{$fn}{'ap_already'} = 1;
  my $row = &FunctionCall('DbGetAutoProvision',$apkey);
  if (!defined $row)
    {
    AE::log note => "#$fn C - no auto-provision profile found for $apkey";
    AE::log info => "#$fn C - tx AP-X";
    my $towrite = "AP-X\r\n";
    $conns{$fn}{'tx'} += length($towrite);
    $hdl->push_write($towrite);
    return;
    }
  # All ok, let's send the data...
  my $towrite = "AP-S 0 ".join(' ',$row->{'ap_stoken'},$row->{'ap_sdigest'},$row->{'ap_msg'})."\r\n";
  AE::log info => "#$fn C - tx AP-S 0 ".join(' ',$row->{'ap_stoken'},$row->{'ap_sdigest'},$row->{'ap_msg'});
  $conns{$fn}{'tx'} += length($towrite);
  $hdl->push_write($towrite);
  }

sub io_line_welcome_31
  {
  my ($fn,$hdl,$line,$clienttype,$username,$password,$vehicleid,$rest) = @_;

  my $permissions = FunctionCall('Authenticate',$username,$password);
  if ($permissions ne '')
    {
    if (! IsPermitted($permissions,'v2'))
      {
      $hdl->destroy;
      delete $conns{$fn};
      AE::log info => "#$fn - - error - Insufficient permission rights for 'v2' access - aborting connection";
      return;
      }
    AE::log info => "#$fn - - authenticated";
    my $orec = FunctionCall('dbGetOwner', $username);
    if (defined $orec)
      {
      AE::log info => "#$fn - - got owner";
      my $vrec;
      if ($vehicleid eq '*')
        {
        my @ovrecs = FunctionCall('dbGetOwnerCars',$username);
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
        $conns{$fn}{'owner'} = $username;
        $conns{$fn}{'vehicleid'} = $vehicleid;
        $conns{$fn}{'owner'} = $username;
        $conns{$fn}{'vkey'} = $vkey;
        $conns{$fn}{'clienttype'} = $clienttype;
        $conns{$fn}{'lastping'} = time;
        $conns{$fn}{'permissions'} = $permissions;

        AE::log debug => "#$fn $clienttype $vkey tx MP-S 1 $username $vehicleid";
        my $towrite = "MP-S 1 $username $vehicleid\r\n";
        $conns{$fn}{'tx'} += length($towrite);
        $hdl->push_write($towrite);
        FunctionCall('DbUtilisation',$username,$vehicleid,$clienttype,length($line)+2,length($towrite));
        &io_login($fn,$hdl,$username,$vehicleid,$clienttype,$rest);
        return;
        }
      }
    }

  $hdl->destroy;
  delete $conns{$fn};
  AE::log info => "#$fn - - error - Incorrect client authentication - aborting connection";
  return;
  }

sub io_login
  {
  my ($fn,$hdl,$owner,$vehicleid,$clienttype,$rest) = @_;

  my $vkey = $owner . '/' . $vehicleid;

  &log($fn, $clienttype, $owner, $vehicleid, "got proto #" . $conns{$fn}{'protscheme'} . "/$clienttype login");

  if ($clienttype eq 'A')      # An APP login
    {
    $app_conns{$vkey}{$fn} = $fn;
    # Notify any listening cars
    my $cfn = $car_conns{$vkey};
    if (defined $cfn)
      {
      &io_tx($cfn, $conns{$cfn}{'handle'}, 'Z', scalar keys %{$app_conns{$vkey}});
      }
    # And notify the app itself
    &io_tx($fn, $hdl, 'Z', (defined $car_conns{$vkey})?"1":"0");
    # Update the app with current stored messages
    my $vrec = &FunctionCall('DbGetVehicle',$owner,$vehicleid);
    my $v_ptoken = $vrec->{'v_ptoken'};
    foreach my $row (FunctionCall('DbGetMessages',$owner,$vehicleid))
      {
      if ($row->{'m_paranoid'})
        {
        if ($v_ptoken ne '')
          {
          &io_tx($fn, $hdl, 'E', 'T'.$v_ptoken);
          $v_ptoken = ''; # Make sure it only gets sent once
          }
        &io_tx($fn, $hdl, 'E', 'M'.$row->{'m_code'}.$row->{'m_msg'});
        }
      else
        {
        &io_tx($fn, $hdl, $row->{'m_code'},$row->{'m_msg'});
        }
      }
    &io_tx($fn, $hdl, 'T', $vrec->{'v_lastupdatesecs'});
    }

  elsif ($clienttype eq 'B')      # A BATCHCLIENT login
    {
    $btc_conns{$vehicleid}{$fn} = $fn;
    # Send peer status
    &io_tx($fn, $hdl, 'Z', (defined $car_conns{$vkey})?"1":"0");
    # Send current stored messages
    my $vrec = &FunctionCall('DbGetVehicle',$owner,$vehicleid);
    my $v_ptoken = $vrec->{'v_ptoken'};
    foreach my $row (FunctionCall('DbGetMessages',$owner,$vehicleid))
      {
      if ($row->{'m_paranoid'})
        {
        if ($v_ptoken ne '')
          {
          &io_tx($fn, $hdl, 'E', 'T'.$v_ptoken);
          $v_ptoken = ''; # Make sure it only gets sent once
          }
        &io_tx($fn, $hdl, 'E', 'M'.$row->{'m_code'}.$row->{'m_msg'});
        }
      else
        {
        &io_tx($fn, $hdl, $row->{'m_code'},$row->{'m_msg'});
        }
      }
    &io_tx($fn, $hdl, 'T', $vrec->{'v_lastupdatesecs'});
    }

  elsif ($clienttype eq 'C')      # A CAR login
    {
    if (defined $car_conns{$vkey})
      {
      # Car is already logged in - terminate it
      &io_terminate($car_conns{$vkey},$conns{$car_conns{$vkey}}{'handle'},$owner,$vehicleid, "error - duplicate car login - clearing first connection");
      }
    $car_conns{$vkey} = $fn;
    # Notify any listening apps & batch clients
    &io_tx_clients($owner, $vehicleid, 'Z', '1');
    # And notify the car itself about listening apps
    my $appcount = (defined $app_conns{$vkey})?(scalar keys %{$app_conns{$vkey}}):0;
    &io_tx($fn, $hdl, 'Z', $appcount);
    }
  }

sub io_terminate
  {
  my ($fn, $handle, $owner, $vehicleid, $msg) = @_;

  my $vkey = $owner . '/' . $vehicleid;

  #AE::log error => $msg if (defined $msg);
  &log($fn, $conns{$fn}{'clienttype'}, $owner, $vehicleid, $msg, "error") if (defined $msg);

  if ((defined $vehicleid)&&(defined $conns{$fn}{'clienttype'}))
    {
    if ($conns{$fn}{'clienttype'} eq 'C')
      {
      delete $car_conns{$vkey};
      # Notify any listening apps & batch clients
      &io_tx_clients($owner, $vehicleid, 'Z', '0');
      # Cleanup group messages
      if (defined $conns{$fn}{'cargroups'})
        {
        foreach (keys %{$conns{$fn}{'cargroups'}})
          {
          delete $group_msgs{$_}{$vkey};
          }
        }
      }
    elsif ($conns{$fn}{'clienttype'} eq 'A')
      {
      &io_cleanup_cmdqueue($fn,"A",$owner,$vehicleid);
      delete $app_conns{$vkey}{$fn};
      # Notify car about new app count
      &io_tx_car($owner, $vehicleid, 'Z', scalar keys %{$app_conns{$vkey}});
      # Cleanup group messages
      if (defined $conns{$fn}{'appgroups'})
        {
        foreach (keys %{$conns{$fn}{'appgroups'}})
          {
          delete $group_subs{$_}{$fn};
          }
        }
      }
    elsif ($conns{$fn}{'clienttype'} eq 'B')
      {
      &io_cleanup_cmdqueue($fn,"B",$owner,$vehicleid);
      delete $btc_conns{$vkey}{$fn};
      }
    }

  $handle->destroy if (defined $handle);
  delete $conns{$fn} if (defined $fn);;

  return;
  }

sub io_cleanup_cmdqueue
  {
  my ($fn,$clienttype,$owner,$vehicleid) = @_;

  my $vkey = $owner . '/' . $vehicleid;

  my $cfn = $car_conns{$vkey};
  my $changed = 0;
  if ((defined $cfn) &&
      (defined $conns{$cfn}) &&
      (defined $conns{$cfn}{'cmdqueue'}) &&
      (scalar @{$conns{$cfn}{'cmdqueue'}} > 0))
    {
    foreach my $fd (@{$conns{$cfn}{'cmdqueue'}})
      {
      if ($fd eq $fn)
        { $fd=0; $changed=1; }
      }
    }
  if ($changed)
    {
    AE::log info => "#$fn $clienttype $vkey cmd cleanup of #$fn for $vehicleid (queue now ".join(',',@{$conns{$cfn}{'cmdqueue'}}).")";
    }
  }

sub io_tx
  {
  my ($fn, $handle, $code, $data) = @_;

  return if ($handle->destroyed);

  my $vid = $conns{$fn}{'vehicleid'};
  my $owner = $conns{$fn}{'owner'};
  my $vkey = $owner . '/' . $vid;
  my $clienttype = $conns{$fn}{'clienttype'}; $clienttype='-' if (!defined $clienttype);

  my $encoded;
  if ($conns{$fn}{'protscheme'} eq '0')
    { $encoded = encode_base64($conns{$fn}{'txcipher'}->RC4("MP-0 $code$data"),''); }
  else
    {
    $encoded = "$code$data";
    }

  AE::log debug => "#$fn $clienttype $vkey tx enc $encoded";
  AE::log info => "#$fn $clienttype $vkey tx msg $code $data";
  FunctionCall('DbUtilisation',$owner,$vid,$clienttype,0,length($encoded)+2);
  $handle->push_write($encoded."\r\n");
  $conns{$fn}{'lasttx'} = time;
  }

# Send message to a CAR
sub io_tx_car
  {
  my ($owner, $vehicleid, $code, $data) = @_;

  my $vkey = $owner . '/' . $vehicleid;

  my $cfn = $car_conns{$vkey};
  if (defined $cfn)
    {
    &io_tx($cfn, $conns{$cfn}{'handle'}, $code, $data);
    }
  }

# Send message to all clients (for a vehicleid)
sub io_tx_clients
  {
  my ($owner, $vehicleid, $code, $data) = @_;

  my $vkey = $owner . '/' . $vehicleid;

  # Send to connected interactive clients
  foreach (keys %{$app_conns{$vkey}})
    {
    my $afn = $_;
    &io_tx($afn, $conns{$afn}{'handle'}, $code, $data);
    }

  # Send to connected batch clients
  foreach (keys %{$btc_conns{$vkey}})
    {
    my $afn = $_;
    &io_tx($afn, $conns{$afn}{'handle'}, $code, $data);
    }
  }

# Message handlers
sub io_message
  {
  my ($fn,$handle,$owner,$vehicleid,$vrec,$code,$data) = @_;

  my $vkey = $owner . '/' . $vehicleid;

  my $clienttype = $conns{$fn}{'clienttype'}; $clienttype='-' if (!defined $clienttype);

  # Handle system-level messages first
  if ($code eq 'A') ## PING
    {
    AE::log info => "#$fn $clienttype $vkey msg ping from $vehicleid";
    &io_tx($fn, $handle, "a", "");
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
    &io_tx_clients($owner, $vehicleid, $code, $data);
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
    my ($appid,$pushtype,$pushkeytype,@vkeys) = split /,/,$data;
    $conns{$fn}{'appid'} = $appid;
    while (scalar @vkeys > 0)
      {
      my $vk_vehicleid = shift @vkeys;
      my $vk_netpass = shift @vkeys;
      my $vk_pushkeyvalue = shift @vkeys;

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
      $conns{$fn}{'ptoken'} = $paranoidtoken;
      &io_tx_clients($owner, $vehicleid, $code, $data); # Send it on to connected apps
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
      my @rows = FunctionCall('dbGetHistoricalDaily',$owner,$vehicleid,'*-OVM-Utilisation',90);
      foreach my $row (@rows)
        {
        $k++;
        &io_tx($fn, $handle, 'c', sprintf('30,0,%d,%d,%s,%s',$k,(scalar @rows),
               $row->{'u_date'},$row->{'data'}));
        }
      if ($k == 0)
        {
        &io_tx($fn, $handle, 'c', '30,1,No GPRS utilisation data available');
        }
      return;
      }
    elsif (($m_code eq $code)&&($data =~ /^(\d+)(,(.+))?$/)&&($1 == 31))
      {
      # Special case of an app requesting (non-paranoid) the historical data summary
      my ($h_since) = $3;
      $h_since='0000-00-00' if (!defined $h_since);
      my @rows = FunctionCall('dbGetHistoricalSummary',$owner,$vehicleid,$h_since);
      my $k = 0;
      foreach my $row (@rows)
        {
        $k++;
        &io_tx($fn, $handle, 'c', sprintf('31,0,%d,%d,%s,%d,%d,%d,%s,%s',$k,(scalar @rows),
               $row->{'h_recordtype'},
               $row->{'distinctrecs'},
               $row->{'totalrecs'},
               $row->{'totalsize'},
               $row->{'first'},
               $row->{'last'}));
        }
      if ($k == 0)
        {
        &io_tx($fn, $handle, 'c', '31,1,No historical data available');
        }
      return;
      }
    elsif (($m_code eq $code)&&($data =~ /^(\d+)(,(.+))?$/)&&($1 == 32))
      {
      # Special case of an app requesting (non-paranoid) the GPRS data
      my ($h_recordtype,$h_since) = split /,/,$3,2;
      $h_since='0000-00-00' if (!defined $h_since);
      my @rows = FunctionCall('dbGetHistoricalRecords', $owner, $vehicleid, $h_recordtype, $h_since);
      my $k = 0;
      foreach my $row (@rows)
        {
        $k++;
        &io_tx($fn, $handle, 'c', sprintf('32,0,%d,%d,%s,%s,%d,%s',$k,(scalar @rows),
               $row->{'h_recordtype'}, $row->{'h_timestamp'}, $row->{'h_recordnumber'}, $row->{'h_data'}));
        }
      if ($k == 0)
        {
        &io_tx($fn, $handle, 'c', '32,1,No historical data available');
        }
      return;
      }
    my $cfn = $car_conns{$vkey};
    if (defined $cfn)
      {
      # Let's record the FN of the app/batch sending this command
      push @{$conns{$cfn}{'cmdqueue'}},$fn;
      AE::log info => "#$fn $clienttype $vkey cmd req for $vehicleid (queue now ".join(',',@{$conns{$cfn}{'cmdqueue'}}).")";
      }
    &io_tx_car($owner, $vehicleid, $code, $data); # Send it on to the car
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
    if (scalar @{$conns{$fn}{'cmdqueue'}} > 0)
      {
      # We have a specific client to send the response to
      my $cfn;
      # Nasty hacky code to determine multi-line responses for command functions 1 and 3
      my ($func,$result,$now,$max,$rest) = split /,/,$data,5;
      if ((($func == 1)||($func == 3)) &&
          (($result != 0)||($now < ($max-1))))
        {
        $cfn = $conns{$fn}{'cmdqueue'}[0];
        }
      $cfn = shift @{$conns{$fn}{'cmdqueue'}} if (!defined $cfn);
      if ($cfn == 0)
        {
        # Client has since disconnected, so ignore it.
        AE::log info => "#$fn $clienttype $vkey cmd rsp discard for $vehicleid (queue now ".join(',',@{$conns{$fn}{'cmdqueue'}}).")";
        }
      else
        {
        # Send to this one specific client
        AE::log info => "#$fn $clienttype $vkey cmd rsp to #$cfn for $vehicleid (queue now ".join(',',@{$conns{$fn}{'cmdqueue'}}).")";
        &io_tx($cfn, $conns{$cfn}{'handle'}, $code, $data);
        }
      }
    else
      {
      # Send it to all clients...
      &io_tx_clients($owner, $vehicleid, $code, $data);
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
      $conns{$fn}{'cargroups'}{$groupid} = 1;
      $group_msgs{$groupid}{$vkey} = $groupmsg;
      # Notify all the apps
      foreach(keys %{$group_subs{$groupid}})
        {
        my $afn = $_;
        &io_tx($afn, $conns{$afn}{'handle'}, $m_code, join(',',$vehicleid,$groupid,$groupmsg));
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
      $conns{$fn}{'appgroups'}{$groupid} = 1;
      $group_subs{$groupid}{$fn} = $fn;
      }
    # Send all outstanding group messages...
    foreach (keys %{$group_msgs{$groupid}})
      {
      my $gvkey = $_;
      my $gvehicleid = $1 if ($gvkey =~ /^.+\/(.+)$/);
      my $msg = $group_msgs{$groupid}{$gvkey};
      &io_tx($fn, $conns{$fn}{'handle'}, 'g', join(',',$gvehicleid,$groupid,$msg));
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
    &io_tx($fn, $conns{$fn}{'handle'}, 'h', $h_ackcode);
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
    my $ptoken = $conns{$fn}{'ptoken'}; $ptoken="" if (!defined $ptoken);
    FunctionCall('DbSaveCarMessage', $owner, $vehicleid, $m_code, 1, UTCTime(), $m_paranoid, $ptoken, $m_data);
    if ($loghistory_tim > 0)
      {
      FunctionCall('DbSaveHistorical',UTCTime(),$m_code,0,$owner,$vehicleid,$m_data,UTCTime(time+$loghistory_tim));
      }
    # And send it on to the apps...
    AE::log debug => "#$fn $clienttype $vkey msg handle $m_code $m_data";
    &io_tx_clients($owner, $vehicleid, $code, $data);
    if ($m_code eq "F")
      {
      # Let's follow up with server version...
      &io_tx_clients($owner, $vehicleid, "f", GetVersion());
      }
    &io_tx_clients($owner, $vehicleid, "T", 0);
    }
  elsif ($clienttype eq 'A')
    {
    # Send it on to the car...
    &io_tx_car($owner, $vehicleid, $code, $data);
    }
  }

1;
