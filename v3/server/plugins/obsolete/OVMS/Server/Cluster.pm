#!/usr/bin/perl
# OVMS Server Cluster

package OVMS::Server::Cluster;

use strict;
use warnings;
use Carp;

use AnyEvent;
use AnyEvent::Log;
use AnyEvent::Handle;

use Exporter qw(import);

our @EXPORT = qw();

my $me; # Reference to our singleton object

my %svr_conns;
my $timeout_svr       = MyConfig()->val('server','timeout_svr',60*60);

# Server PUSH tickers
my $svrtim = AnyEvent->timer (after => 30, interval => 30, cb => \&svr_tim);
my $svrtim2 = AnyEvent->timer (after => 300, interval => 300, cb => \&svr_tim2);

# A server client
my $svr_handle;
my $svr_client_token;
my $svr_client_digest;
my $svr_txcipher;
my $svr_rxcipher;
my $svr_server   = MyConfig()->val('master','server');
my $svr_port     = MyConfig()->val('master','port',6867);
my $svr_vehicle  = MyConfig()->val('master','vehicle');
my $svr_pass     = MyConfig()->val('master','password');
if (defined $svr_server)
  {
  &svr_client();
  }

on_timeout
elsif ($clienttype eq 'S')
  {
  if (($lastrx+$timeout_svr)<$now)
    {
    # The SVR has been unresponsive for timeout_svr seconds - time to disconnect it
    &io_terminate($fn,$hdl,$vid, "timeout svr due to inactivity");
    return;
    }
  }

io_login
elsif ($clienttype eq 'S')
  {
  #
  # A SERVER login
  #
  if (defined $svr_conns{$vehicleid})
    {
    # Server is already logged in - terminate it
    &io_terminate($svr_conns{$vehicleid},$conns{$svr_conns{$vehicleid}}{'handle'},$vehicleid, "error - duplicate server login - clearing first connection");
    }
  $svr_conns{$vehicleid} = $fn;
  my ($svrupdate_v,$svrupdate_o) = ($1,$2) if ($rest =~ /^(\S+ \S+) (\S+ \S+)/);
  $conns{$fn}{'svrupdate_v'} = $svrupdate_v;
  $conns{$fn}{'svrupdate_o'} = $svrupdate_o;
  &svr_push($fn,$vehicleid);
  }

io_terminate
elsif ($conns{$fn}{'clienttype'} eq 'S')
  {
  delete $svr_conns{$vehicleid};
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

  return $self;
  }

sub init
  {
  my ($self) = @_;
  }


sub svr_tim
  {
  return if (scalar keys %svr_conns == 0);

  # Drupal -> ovms_owners maintenance
  $db->do('INSERT INTO ovms_owners SELECT uid,name,mail,pass,status,0,utc_timestamp() FROM users WHERE users.uid NOT IN (SELECT owner FROM ovms_owners)');
  $db->do('UPDATE ovms_owners LEFT JOIN users ON users.uid=ovms_owners.owner '
        . 'SET ovms_owners.pass=users.pass, ovms_owners.status=users.status, ovms_owners.name=users.name, ovms_owners.mail=users.mail, deleted=0, changed=UTC_TIMESTAMP() '
        . 'WHERE users.pass<>ovms_owners.pass OR users.status<>ovms_owners.status OR users.name<>ovms_owners.name OR users.mail<>ovms_owners.mail');
  $db->do('UPDATE ovms_owners SET deleted=1,changed=UTC_TIMESTAMP() WHERE deleted=0 AND owner NOT IN (SELECT uid FROM users)');

  my %last;
  my $sth = $db->prepare('SELECT v_server,MAX(changed) AS lu FROM ovms_cars WHERE v_type="CAR" GROUP BY v_server');
  $sth->execute();
  while (my $row = $sth->fetchrow_hashref())
    {
    $last{$row->{'v_server'}} = $row->{'lu'};
    }

  my $last_o;
  $sth = $db->prepare('SELECT MAX(changed) as lu FROM ovms_owners');
  $sth->execute();
  while (my $row = $sth->fetchrow_hashref())
    {
    $last_o = $row->{'lu'};
    }

  foreach (keys %svr_conns)
    {
    my $vehicleid = $_;
    my $fn = $svr_conns{$vehicleid};
    my $svrupdate_v = $conns{$fn}{'svrupdate_v'};
    my $svrupdate_o = $conns{$fn}{'svrupdate_o'};
    my $lw = $last{'*'}; $lw='0000-00-00 00:00:00' if (!defined $lw);
    my $ls = $last{$vehicleid}; $ls='0000-00-00 00:00:00' if (!defined $ls);
    if (($lw gt $svrupdate_v)||($ls gt $svrupdate_v)||($last_o gt $svrupdate_o))
      {
      &svr_push($fn,$vehicleid);
      }
    }
  }

sub svr_tim2
  {
  if ((!defined $svr_handle)&&(defined $svr_server))
    {
    &svr_client();
    }
  }

sub svr_push
  {
  my ($fn,$vehicleid) = @_;

  # Push updated cars to the specified server
  return if (!defined $svr_conns{$vehicleid}); # Make sure it is a server

  my $sth = $db->prepare('SELECT * FROM ovms_cars WHERE v_type="CAR" AND v_server IN ("*",?) AND changed>? ORDER BY changed');
  $sth->execute($vehicleid,$conns{$fn}{'svrupdate_v'});
  while (my $row = $sth->fetchrow_hashref())
    {
    &io_tx($fn, $conns{$fn}{'handle'}, 'RV',
            join(',',$row->{'vehicleid'},$row->{'owner'},$row->{'carpass'},
                     $row->{'v_server'},$row->{'deleted'},$row->{'changed'}));
    $conns{$fn}{'svrupdate_v'} = $row->{'changed'};
    }

  $sth = $db->prepare('SELECT * FROM ovms_owners WHERE changed>? ORDER BY changed');
  $sth->execute($conns{$fn}{'svrupdate_o'});
  while (my $row = $sth->fetchrow_hashref())
    {
    &io_tx($fn, $conns{$fn}{'handle'}, 'RO',
            join(',',$row->{'owner'},$row->{'name'},$row->{'mail'},
                     $row->{'pass'},$row->{'status'},$row->{'deleted'},$row->{'changed'}));
    $conns{$fn}{'svrupdate_o'} = $row->{'changed'};
    }
  }

sub svr_client
  {
  tcp_connect $svr_server, $svr_port, sub
    {
    my ($fh) = @_;

    $svr_handle = new AnyEvent::Handle(fh => $fh, on_error => \&svr_error, on_rtimeout => \&svr_timeout, keepalive => 1, no_delay => 1, rtimeout => 60*60);
    $svr_handle->push_read (line => \&svr_welcome);

    my $sth = $db->prepare('SELECT MAX(changed) AS mc FROM ovms_cars WHERE v_type="CAR"');
    $sth->execute();
    my $row = $sth->fetchrow_hashref();
    my $last_v = $row->{'mc'}; $last_v = '0000-00-00 00:00:00' if (!defined $last_v);

    $sth = $db->prepare('SELECT MAX(changed) AS mc FROM ovms_owners');
    $sth->execute();
    $row = $sth->fetchrow_hashref();
    my $last_o = $row->{'mc'}; $last_o = '0000-00-00 00:00:00' if (!defined $last_o);

    $svr_client_token = '';
    foreach (0 .. 21)
      { $svr_client_token .= substr($b64tab,rand(64),1); }
    my $client_hmac = Digest::HMAC->new($svr_pass, "Digest::MD5");
    $client_hmac->add($svr_client_token);
    $svr_client_digest = $client_hmac->b64digest();
    $svr_handle->push_write("MP-S 0 $svr_client_token $svr_client_digest $svr_vehicle $last_v $last_o\r\n");
    }
  }

sub svr_welcome
  {
  my ($hdl, $line) = @_;

  my $fn = $hdl->fh->fileno();
  AE::log info => "#$fn - - svr welcome $line";

  my ($welcome,$crypt,$server_token,$server_digest) = split /\s+/,$line;

  my $d_server_digest = decode_base64($server_digest);
  my $client_hmac = Digest::HMAC->new($svr_pass, "Digest::MD5");
  $client_hmac->add($server_token);
  if ($client_hmac->digest() ne $d_server_digest)
    {
    AE::log error => "#$fn - - svr server digest is invalid - aborting";
    undef $svr_handle;
    return;
    }

  $client_hmac = Digest::HMAC->new($svr_pass, "Digest::MD5");
  $client_hmac->add($server_token);
  $client_hmac->add($svr_client_token);
  my $client_key = $client_hmac->digest;

  $svr_txcipher = Crypt::RC4::XS->new($client_key);
  $svr_txcipher->RC4(chr(0) x 1024); # Prime the cipher
  $svr_rxcipher = Crypt::RC4::XS->new($client_key);
  $svr_rxcipher->RC4(chr(0) x 1024); # Prime the cipher

  $svr_handle->push_read (line => \&svr_line);
  }

sub svr_line
  {
  my ($hdl, $line) = @_;
  my $fn = $hdl->fh->fileno();

  $svr_handle->push_read (line => \&svr_line);

  my $dline = $svr_rxcipher->RC4(decode_base64($line));
  AE::log debug => "#$fn - - svr got $dline";

  if ($dline =~ /^MP-0 A/)
    {
    $svr_handle->push_write(encode_base64($svr_txcipher->RC4("MP-0 a"),''));
    }
  elsif ($dline =~ /MP-0 RV(.+)/)
    {
    my ($vehicleid,$owner,$carpass,$v_server,$deleted,$changed) = split(/,/,$1);
    AE::log info => "#$fn - - svr got vehicle record update $vehicleid ($changed)";

    $db->do('INSERT INTO ovms_cars (vehicleid,owner,carpass,v_server,deleted,changed,v_lastupdate) '
          . 'VALUES (?,?,?,?,?,?,NOW()) '
          . 'ON DUPLICATE KEY UPDATE owner=?, carpass=?, v_server=?, deleted=?, changed=?',
            undef,
            $vehicleid,$owner,$carpass,$v_server,$deleted,$changed,$owner,$carpass,$v_server,$deleted,$changed);
    }
  elsif ($dline =~ /MP-0 RO(.+)/)
    {
    my ($owner,$name,$mail,$pass,$status,$deleted,$changed) = split(/,/,$1);
    AE::log info => "#$fn - - svr got owner record update $owner ($changed)";

    $db->do('INSERT INTO ovms_owners (owner,name,mail,pass,status,deleted,changed) '
          . 'VALUES (?,?,?,?,?,?,?) '
          . 'ON DUPLICATE KEY UPDATE name=?, mail=?, pass=?, status=?, deleted=?, changed=?',
            undef,
            $owner,$name,$mail,$pass,$status,$deleted,$changed,
            $name,$mail,$pass,$status,$deleted,$changed);
    }
  }

sub svr_error
  {
  my ($hdl, $fatal, $msg) = @_;
  my $fn = $hdl->fh->fileno();

  AE::log note => "#$fn - - svr got disconnect from remote";

  undef $svr_handle;
  }

sub svr_timeout
  {
  my ($hdl) = @_;
  my $fn = $hdl->fh->fileno();

  AE::log note => "#$fn - - svr got timeout from remote";

  undef $svr_handle;
  }

1;
