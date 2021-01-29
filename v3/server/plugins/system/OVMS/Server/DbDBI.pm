#!/usr/bin/perl

########################################################################
# Database: DBI (for perl DBI databases)
#
# This plugin provides an interface to databases supported by perl's
# DBI system. In particular, it supports the standard MySQL database.

package OVMS::Server::DbDBI;

use strict;
use warnings;
use Carp;

use AnyEvent;
use AnyEvent::Log;
use DBI;
use OVMS::Server::Core;
use OVMS::Server::Plugin;

use Exporter qw(import);

our @EXPORT = qw();

# Database: DBI based database

my $me;            # Reference to our singleton object
my $db;            # Database connection object
my $db_tim;        # Database
my %utilisations;
use vars qw{
  };

sub new
  {
  my $class = shift;
  $class = ref($class) || $class;
  my $self = {@_};
  bless( $self, $class );

  $me = $self;

  # Database ticker
  $db = DBI->connect(MyConfig()->val('db','path'),MyConfig()->val('db','user'),MyConfig()->val('db','pass'));
  if (!defined $db)
    {
    AE::log error => "- - - fatal: cannot connect to database ($!)";
    exit(1);
    }
  $db->{mysql_auto_reconnect} = 1;
  $db->do("SET NAMES utf8");
  $db_tim = AnyEvent->timer (after => 60, interval => 60, cb => \&_db_housekeep);

  RegisterFunction('DbDoSQL',\&DbDoSQL);
  RegisterFunction('DbUtilisation',\&DbUtilisation);
  RegisterFunction('DbHasVehicle',\&DbHasVehicle);
  RegisterFunction('DbGetVehicle',\&DbGetVehicle);
  RegisterFunction('DbGetAutoProvision',\&DbGetAutoProvision);
  RegisterFunction('DbGetMessages',\&DbGetMessages);
  RegisterFunction('DbGetHistoricalDaily',\&DbGetHistoricalDaily);
  RegisterFunction('DbGetHistoricalRecords',\&DbGetHistoricalRecords);
  RegisterFunction('DbGetHistoricalSummary',\&DbGetHistoricalSummary);
  RegisterFunction('DbGetNotify',\&DbGetNotify);
  RegisterFunction('DbGetOwner',\&DbGetOwner);
  RegisterFunction('DbGetOwnerCars',\&DbGetOwnerCars);
  RegisterFunction('DbSaveHistorical',\&DbSaveHistorical);
  RegisterFunction('DbSaveHistoricalNumeric',\&DbSaveHistoricalNumeric);
  RegisterFunction('DbRegisterPushNotify',\&DbRegisterPushNotify);
  RegisterFunction('DbInvalidateParanoidMessages',\&DbInvalidateParanoidMessages);
  RegisterFunction('DbSaveCarMessage',\&DbSaveCarMessage);
  RegisterFunction('DbGetToken',\&DbGetToken);
  RegisterFunction('DbGetOwnerTokens',\&DbGetOwnerTokens);
  RegisterFunction('DbSaveToken',\&DbSaveToken);
  RegisterFunction('DbDeleteToken',\&DbDeleteToken);
  RegisterFunction('DbClearOwnerCaches',\&DbClearOwnerCaches);

  return $self;
  }

sub _db_housekeep
  {
  if (!defined $db)
    {
    $db = DBI->connect(MyConfig()->val('db','path'),MyConfig()->val('db','user'),MyConfig()->val('db','pass'));
    return;
    }
  if (! $db->ping())
    {
    AE::log error => "- - - lost database connection - reconnecting...";
    $db = DBI->connect(MyConfig()->val('db','path'),MyConfig()->val('db','user'),MyConfig()->val('db','pass'));
    }
  if (defined $db)
    {
    $db->do('DELETE FROM ovms_historicalmessages WHERE h_expires<UTC_TIMESTAMP();');

    # Add collected utilisations to database
    CONN: foreach my $key (keys %utilisations)
      {
      my $vid = $utilisations{$key}{'vehicleid'};
      my $ownername = $utilisations{$key}{'ownername'};
      my $clienttype = $utilisations{$key}{'clienttype'};
      next CONN if ((!defined $clienttype)||($clienttype eq '-'));
      next CONN if (!defined $vid);
      my $rx = $utilisations{$key}{'rx'}; $rx=0 if (!defined $rx);
      my $tx = $utilisations{$key}{'tx'}; $tx=0 if (!defined $tx);
      next CONN if (($rx+$tx)==0);
      my ($u_c_rx, $u_c_tx, $u_a_rx, $u_a_tx) = (0,0,0,0);
      if ($clienttype eq 'C')
        {
        $u_c_rx += $tx;
        $u_c_tx += $rx;
        }
      elsif ($clienttype eq 'A')
        {
        $u_a_rx += $tx;
        $u_a_tx += $rx;
        }
      DbSaveHistoricalNumeric(UTCDateFull(),'*-OVM-Utilisation',0,$ownername,$vid,$u_c_rx,UTCDateFull(time+86400));
      DbSaveHistoricalNumeric(UTCDateFull(),'*-OVM-Utilisation',1,$ownername,$vid,$u_c_tx,UTCDateFull(time+86400));
      DbSaveHistoricalNumeric(UTCDateFull(),'*-OVM-Utilisation',2,$ownername,$vid,$u_a_rx,UTCDateFull(time+86400));
      DbSaveHistoricalNumeric(UTCDateFull(),'*-OVM-Utilisation',3,$ownername,$vid,$u_a_tx,UTCDateFull(time+86400));
      }
    %utilisations = ();
    }
  }

my %cache_ownernamebyid = ();
sub DbOwnerNameByID
  {
  my ($id) = @_;

  return $cache_ownernamebyid{$id} if (defined $cache_ownernamebyid{$id});

  my $sth = $db->prepare('SELECT * FROM ovms_owners WHERE `owner`=? and `status`=1 AND deleted="0000-00-00 00:00:00"');
  $sth->execute($id);
  my $row = $sth->fetchrow_hashref();

  if (defined $row)
    {
    $cache_ownernamebyid{$id} = $row->{'name'};
    return $row->{'name'};
    }
  else
    {
    return undef;
    }
  }

my %cache_owneridbyname = ();
sub DBOwnerIDByName
  {
  my ($name) = @_;

  return $cache_owneridbyname{$name} if (defined $cache_owneridbyname{$name});

  my $sth = $db->prepare('SELECT * FROM ovms_owners WHERE `name`=? and `status`=1 AND deleted="0000-00-00 00:00:00"');
  $sth->execute($name);
  my $row = $sth->fetchrow_hashref();

  if (defined $row)
    {
    $cache_owneridbyname{$name} = $row->{'owner'};
    return $row->{'owner'};
    }
  else
    {
    return undef;
    }
  }

sub DbClearOwnerCaches
  {
  %cache_ownernamebyid = ();
  %cache_owneridbyname = ();
  }

sub DbDoSQL
  {
  my ($sql) = @_;

  $db->do($sql);
  }

sub DbUtilisation
  {
  my ($ownername, $vehicleid, $clienttype, $rx, $tx) = @_;

  return if ((!defined $clienttype)||($clienttype eq '-'));
  return if ((!defined $vehicleid)||($vehicleid eq '-'));

  $utilisations{$vehicleid.'-'.$clienttype}{'rx'} += $rx;
  $utilisations{$vehicleid.'-'.$clienttype}{'tx'} += $tx;
  $utilisations{$vehicleid.'-'.$clienttype}{'vehicleid'} = $vehicleid;
  $utilisations{$vehicleid.'-'.$clienttype}{'ownername'} = $ownername;
  $utilisations{$vehicleid.'-'.$clienttype}{'clienttype'} = $clienttype;
  }

sub DbHasVehicle
  {
  my ($ownername, $vehicleid) = @_;

  return 0 if ((!defined $ownername)||(!defined $vehicleid));

  my $sth = $db->prepare('SELECT vehicleid '
                       . 'FROM ovms_cars WHERE owner=? AND vehicleid=? AND deleted="0"');
  $sth->execute(DBOwnerIDByName($ownername), $vehicleid);
  my $row = $sth->fetchrow_hashref();

  return (defined $row);
  }

sub DbGetVehicle
  {
  my ($ownername, $vehicleid) = @_;

  my $row;

  if ((!defined $ownername)||($ownername eq ''))
    {
    my $sth = $db->prepare('SELECT *,TIME_TO_SEC(TIMEDIFF(UTC_TIMESTAMP(),v_lastupdate)) as v_lastupdatesecs '
                         . 'FROM ovms_cars WHERE vehicleid=? AND deleted="0"');
    $sth->execute($vehicleid);
    $row = $sth->fetchrow_hashref();
    $row->{'owner'} = DbOwnerNameByID($row->{'owner'}) if (defined $row);
    }
  else
    {
    my $sth = $db->prepare('SELECT *,TIME_TO_SEC(TIMEDIFF(UTC_TIMESTAMP(),v_lastupdate)) as v_lastupdatesecs '
                         . 'FROM ovms_cars WHERE owner=? AND vehicleid=? AND deleted="0"');
    $sth->execute(DBOwnerIDByName($ownername), $vehicleid);
    $row = $sth->fetchrow_hashref();
    $row->{'owner'} = $ownername if (defined $row);
    }

  return $row;
  }

sub DbGetAutoProvision
  {
  my ($apkey) = @_;

  my $sth = $db->prepare('SELECT * FROM ovms_autoprovision WHERE ap_key=? and deleted=0');
  $sth->execute($apkey);
  my $row = $sth->fetchrow_hashref();
  $row->{'owner'} = DbOwnerNameByID($row->{'owner'}) if (defined $row);

  return $row;
  }

sub DbGetMessages
  {
  my ($ownername,$vehicleid) = @_;

  my $ownerid = DBOwnerIDByName($ownername);
  my $sth = $db->prepare('SELECT * FROM ovms_carmessages '
                       . 'WHERE owner=? AND vehicleid=? AND m_valid=1 '
                       . 'ORDER BY FIELD(m_code,"S","F") DESC,m_code ASC');
  $sth->execute($ownerid, $vehicleid);
  my @rows;
  while (my $row = $sth->fetchrow_hashref())
    {
    $row->{'owner'} = $ownername;
    push @rows,$row;
    }

  return @rows;
  }

sub DbGetHistoricalDaily
  {
  my ($ownername, $vehicleid, $recordtype, $days) = @_;

  $recordtype = '*-OVM-Utilisation' if (!defined $recordtype);
  $days = 90 if (!defined $days);

  my $sth = $db->prepare('SELECT vehicleid,left(h_timestamp,10) AS u_date,group_concat(h_data ORDER BY h_recordnumber) AS data '
                       . 'FROM ovms_historicalmessages WHERE owner=? AND vehicleid=? AND h_recordtype=? '
                       . 'GROUP BY vehicleid,u_date,h_recordtype ORDER BY h_timestamp desc LIMIT ' . $days);
  $sth->execute(DBOwnerIDByName($ownername), $vehicleid, $recordtype);

  my @rows;
  while (my $row = $sth->fetchrow_hashref())
    {
    $row->{'owner'} = $ownername;
    push @rows,$row;
    }

  return @rows;
  }

sub DbGetHistoricalRecords
  {
  my ($ownername, $vehicleid, $recordtype, $since) = @_;

  $since='0000-00-00' if (!defined $since);

  my $sth = $db->prepare('SELECT * FROM ovms_historicalmessages WHERE owner=? AND vehicleid=? AND h_recordtype=? AND h_timestamp>? ORDER BY h_timestamp,h_recordnumber');
  $sth->execute(DBOwnerIDByName($ownername),$vehicleid,$recordtype,$since);

  my @rows;
  while (my $row = $sth->fetchrow_hashref())
    {
    $row->{'owner'} = $ownername;
    push @rows,$row;
    }

  return @rows;
  }

sub DbGetHistoricalSummary
  {
  my ($ownername, $vehicleid, $since) = @_;

  $since='0000-00-00' if (!defined $since);

  my $sth = $db->prepare('SELECT h_recordtype,COUNT(DISTINCT h_recordnumber) AS distinctrecs, COUNT(*) AS totalrecs, '
                       . 'SUM(LENGTH(h_recordtype)+LENGTH(h_data)+LENGTH(vehicleid)+20) AS totalsize, MIN(h_timestamp) AS first, MAX(h_timestamp) AS last '
                       . 'FROM ovms_historicalmessages WHERE owner=? AND vehicleid=? AND h_timestamp>? '
                       . 'GROUP BY h_recordtype ORDER BY h_recordtype;');
  $sth->execute(DBOwnerIDByName($ownername),$vehicleid,$since);

  my @rows;
  while (my $row = $sth->fetchrow_hashref())
    {
    $row->{'owner'} = $ownername;
    push @rows,$row;
    }

  return @rows;
  }

sub DbGetNotify
  {
  my ($ownername, $vehicleid) = @_;

  my $sth = $db->prepare('SELECT * FROM ovms_notifies WHERE owner=? AND vehicleid=? and active=1');
  $sth->execute(DBOwnerIDByName($ownername), $vehicleid);

  my @rows;
  while (my $row = $sth->fetchrow_hashref())
    {
    $row->{'owner'} = $ownername;
    push @rows,$row;
    }

  return @rows;
  }

sub DbGetOwner
  {
  my ($ownername) = @_;

  my $sth = $db->prepare('SELECT * FROM ovms_owners WHERE `name`=? and `status`=1 AND deleted="0000-00-00 00:00:00"');
  $sth->execute($ownername);
  my $row = $sth->fetchrow_hashref();
  if (defined $row)
    {
    $row->{'owner'} = $ownername;
    delete $row->{'name'};
    }
  return $row;
  }

sub DbGetOwnerCars
  {
  my ($ownername) = @_;

  my $sth = $db->prepare('SELECT * FROM ovms_cars WHERE owner=? AND deleted=0 ORDER BY vehicleid');
  $sth->execute(DBOwnerIDByName($ownername));

  my @rows;
  while (my $row = $sth->fetchrow_hashref())
    {
    $row->{'owner'} = $ownername;
    push @rows,$row;
    }

  return @rows;
  }

sub DbSaveHistoricalNumeric
  {
  my ($timestamp, $recordtype, $recordnumber, $ownername, $vehicleid, $data, $expires) = @_;

  $db->do('INSERT INTO ovms_historicalmessages (owner,vehicleid,h_timestamp,h_recordtype,h_recordnumber,h_data,h_expires) '
        . 'VALUES (?,?,?,?,?,?,?) '
        . 'ON DUPLICATE KEY UPDATE h_data=h_data+?, h_expires=?',
          undef,
          DBOwnerIDByName($ownername), $vehicleid, $timestamp, $recordtype, $recordnumber, $data, $expires,
          $data,$expires);
  }

sub DbSaveHistorical
  {
  my ($timestamp, $recordtype, $recordnumber, $ownername, $vehicleid, $data, $expires) = @_;

  $db->do('INSERT INTO ovms_historicalmessages (owner,vehicleid,h_timestamp,h_recordtype,h_recordnumber,h_data,h_expires) '
        . 'VALUES (?,?,?,?,?,?,?) '
        . 'ON DUPLICATE KEY UPDATE h_data=?, h_expires=?',
          undef,
          DBOwnerIDByName($ownername), $vehicleid, $timestamp, $recordtype, $recordnumber, $data, $expires,
          $data,$expires);
  }

sub DbRegisterPushNotify
  {
  my ($ownername, $vehicleid, $appid, $pushtype, $pushkeytype, $pushkeyvalue) = @_;

  $db->do("INSERT INTO ovms_notifies (owner,vehicleid,appid,pushtype,pushkeytype,pushkeyvalue,lastupdated) "
        . "VALUES (?,?,?,?,?,?,UTC_TIMESTAMP()) ON DUPLICATE KEY UPDATE "
        . "lastupdated=UTC_TIMESTAMP(), pushkeytype=?, pushkeyvalue=?",
          undef,
          DBOwnerIDByName($ownername), $vehicleid, $appid, $pushtype, $pushkeytype, $pushkeyvalue,
          $pushkeytype, $pushkeyvalue);
  }

sub DbInvalidateParanoidMessages
  {
  my ($ownername,$vehicleid,$paranoidtoken) = @_;

  $db->do("UPDATE ovms_carmessages SET m_valid=0 WHERE owner=? AND vehicleid=? AND m_paranoid=1 AND m_ptoken != ?",
          undef,
          DBOwnerIDByName($ownername),$vehicleid,$paranoidtoken);
  $db->do("UPDATE ovms_cars SET v_ptoken=? WHERE owner=? AND vehicleid=?",
          undef,
          $paranoidtoken,DBOwnerIDByName($ownername),$vehicleid);
  }

sub DbSaveCarMessage
  {
  my ($ownername, $vehicleid, $code, $valid, $timestamp, $paranoid, $ptoken, $msg) = @_;

  $db->do("INSERT INTO ovms_carmessages (owner,vehicleid,m_code,m_valid,m_msgtime,m_paranoid,m_ptoken,m_msg) "
        . "VALUES (?,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE "
        . "m_valid=?, m_msgtime=?, m_paranoid=?, m_ptoken=?, m_msg=?",
          undef,
          DBOwnerIDByName($ownername), $vehicleid, $code, $valid, $timestamp, $paranoid, $ptoken, $msg,
          $valid, $timestamp, $paranoid, $ptoken, $msg);
  $db->do("UPDATE ovms_cars SET v_lastupdate=UTC_TIMESTAMP() WHERE owner=? AND vehicleid=?",
          undef,
          DBOwnerIDByName($ownername), $vehicleid);
  }

sub DbGetToken
  {
  my ($ownername, $token) = @_;

  my $sth = $db->prepare('SELECT * FROM ovms_apitokens WHERE owner=? AND token=?');
  $sth->execute(DBOwnerIDByName($ownername), $token);
  my $row = $sth->fetchrow_hashref();

  return $row;
  }

sub DbGetOwnerTokens
  {
  my ($ownername) = @_;

  my $sth = $db->prepare('SELECT * FROM ovms_apitokens WHERE owner=?');
  $sth->execute(DBOwnerIDByName($ownername));
  my @rows;
  while (my $row = $sth->fetchrow_hashref())
    {
    $row->{'owner'} = $ownername;
    push @rows,$row;
    }

  return @rows;
  }

sub DbSaveToken
  {
  my ($ownername, $token, $application, $purpose, $permit) = @_;

  $application = 'not specified' if (!defined $application);
  $purpose = 'not specified' if (!defined $purpose);
  $permit = 'none' if (!defined $permit);

  $db->do("INSERT INTO ovms_apitokens (owner,token,application,purpose,permit,created,refreshed,lastused) "
        . "VALUES (?,?,?,?,?,UTC_TIMESTAMP(),UTC_TIMESTAMP(),UTC_TIMESTAMP()) "
        . "ON DUPLICATE KEY UPDATE "
        . "application=?, purpose=?, permit=?",
          undef,
          DBOwnerIDByName($ownername), $token, $application, $purpose, $permit,
          $application, $purpose, $permit);
  }

sub DbDeleteToken
  {
  my ($ownername, $token) = @_;

  $db->do("DELETE FROM ovms_apitokens WHERE owner=? AND token=?",
          undef,
          DBOwnerIDByName($ownername), $token);
  }

1;
