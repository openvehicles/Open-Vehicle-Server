#!/usr/bin/perl

use EV;
use AnyEvent;
use AnyEvent::Handle;
use AnyEvent::Socket;
use Digest::MD5;
use Digest::HMAC;
use Crypt::RC4::XS;
use MIME::Base64;
use IO::Socket::INET;
use Math::Trig qw(deg2rad pi great_circle_distance asin acos);

my $b64tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

my $shared_secret = "RALLY";
print STDERR "Shared Secret is: ",$shared_secret,"\n";

#####
##### CONNECT
#####

my $sock = IO::Socket::INET->new(PeerAddr => '127.0.0.1',
                                 PeerPort => '6867',
                                 Proto    => 'tcp');

#####
##### CLIENT
#####

print STDERR "I am the rally car\n";

rand;
my $client_token;
foreach (0 .. 21)
  { $client_token .= substr($b64tab,rand(64),1); }
print STDERR "  Client token is  $client_token\n";

my $client_hmac = Digest::HMAC->new($shared_secret, "Digest::MD5");
$client_hmac->add($client_token);
my $client_digest = $client_hmac->b64digest();
print STDERR "  Client digest is $client_digest\n";

print $sock "MP-C 0 $client_token $client_digest RALLY\r\n";

my $line = <$sock>;
chop $line;
chop $line;
print STDERR "  Received $line from server\n";
my ($welcome,$crypt,$server_token,$server_digest) = split /\s+/,$line;

print STDERR "  Received $server_token $server_digest from server\n";

my $d_server_digest = decode_base64($server_digest);
my $client_hmac = Digest::HMAC->new($shared_secret, "Digest::MD5");
$client_hmac->add($server_token);
if ($client_hmac->digest() ne $d_server_digest)
  {
  print STDERR "  Client detects server digest is invalid - aborting\n";
  exit(1);
  }
print STDERR "  Client verification of server digest is ok\n";

$client_hmac = Digest::HMAC->new($shared_secret, "Digest::MD5");
$client_hmac->add($server_token);
$client_hmac->add($client_token);
my $client_key = $client_hmac->digest;
print STDERR "  Client version of shared key is: ",encode_base64($client_key,''),"\n";

our $txcipher = Crypt::RC4::XS->new($client_key);
$txcipher->RC4(chr(0) x 1024); # Prime the cipher
our $rxcipher = Crypt::RC4::XS->new($client_key);
$rxcipher->RC4(chr(0) x 1024); # Prime the cipher

my $encrypted = encode_base64($txcipher->RC4("MP-0 A"),'');
print STDERR "  Sending message $encrypted\n";
print $sock "$encrypted\r\n";

$line = <$sock>;
chop $line;
chop $line;
print STDERR "  Received $line from server\n";
print STDERR "  Server message decodes to: ",$rxcipher->RC4(decode_base64($line)),"\n";

# Now, let's go for it...
my $rally_data; open $rally_data,"<ovms_rally.data";
my $rally_line = <$rally_data>; chop $rally_line;
my ($lat,$lon,$bearing,$dist,$speed) = split /\s+/,$rally_line;

my ($soc,$kmideal,$kmest,$state,$mode,$volts,$amps) = (87,int((87.0/100.0)*350.0),int((87.0/100.0)*350.0)-20,'done','standard',0,0);
my ($substate,$stateN,$modeN) = (7,13,0);
my $trip = $dist;
my $odometer = $dist;
my $chargetime = 0;
my $appsconnected = 0;
my $lastupdated = 0;

my ($ambiant,$nextambiant)=(0,0);
&getambiant();

srand();

my $handle = new AnyEvent::Handle(fh => $sock, on_error => \&io_error, keepalive => 1, no_delay => 1);
$handle->push_read (line => \&io_line);
&statmsg();

my $tim = AnyEvent->timer (after => 2, interval => 2, cb => \&io_tim);

# Main event loop...
EV::loop();

sub io_error
  {
  my ($hdl, $fatal, $msg) = @_;

  undef $hdl;
  undef $handle;
  print "Got error: $msg\n";
  sleep 30;
  exec './ovms_rally.pl';
  }

sub io_tim
  {
  my ($hdl) = @_;

  my $rally_line = <$rally_data>;
  if (!defined $rally_line)
    {
    close $rally_data;
    open $rally_data,"<ovms_rally.data";
    $trip = 0;
    ($soc,$kmideal,$kmest,$state,$mode,$volts,$amps) = (87,int((87.0/100.0)*350.0),int((87.0/100.0)*350.0)-20,'done','standard',0,0);
    print "End-of-rally - restarting...\n";
    return;
    }

  ($lat,$lon,$bearing,$dist,$speed) = split /\s+/,$rally_line;
  $trip += $dist;
  $odometer += $dist;
  $kmideal = $kmideal-$dist;
  $kmest = int($kmideal*0.9);
  $soc = int(100*$kmideal/350);

  print "Rallying ",$trip,"km at ",$speed,"kph ",$bearing," degrees - now SOC is $soc ($kmideal,$kmest)\n";

  if (--$nextambiant <= 0)
    {
    &getambiant();
    }

  &statmsg();
  }

sub io_line
  {
  my ($hdl, $line) = @_;

  print "  Received $line from server\n";

  $line = $rxcipher->RC4(decode_base64($line));
  print "  Server message decodes to: $line\n";
  if ($line =~ /^MP-0 A/)
    {
    my $encrypted = encode_base64($txcipher->RC4("MP-0 a"),'');
    print STDERR "  Sending message $encrypted\n";
    print $hdl->push_write("$encrypted\r\n");
    }
  elsif ($line =~ /^MP-0 Z(\d+)/)
    { # One or more apps connected...
    $appsconnected = $1;
    if ($appsconnected>0)
      {
      $lastupdate = 0;
      &statmsg();
      }
    }
  elsif ($line =~ /^MP-0 C(\d+)/)
    { # A command...
    my $encrypted = encode_base64($txcipher->RC4("MP-0 c$1,1,Comand refused"),'');
    print STDERR "  Sending message $encrypted\n";
    print $hdl->push_write("$encrypted\r\n");
    &statmsg();
    }
  $hdl->push_read (line => \&io_line);
  }

sub statmsg
  {
  my ($front,$back) = ($ambiant+2,$ambiant+6);
  my ($pem,$motor,$battery) = ($ambiant+10,$ambiant+20,$ambiant+5);
  my $cb = ($travelling == 0)?124:160;
  my ($ikmideal,$ikmest) = (int($kmideal),int($kmest));
  my ($itrip,$iodometer) = (int($trip*10),int($odometer*10));

  my $updates=0;
  $updates+= &sendmessage("F","1.2.0,VIN123456789012346,5,0,TR");
  $updates+= &sendmessage("S","$soc,K,$volts,$amps,$state,$mode,$ikmideal,$ikmest,13,$chargetime,0,0,$substate,$stateN,$modeN");
  $updates+= &sendmessage("L","$lat,$lon,$bearing,0,1,1");
  $updates+= &sendmessage("D","$cb,0,5,$pem,$motor,$battery,$itrip,$iodometer,$speed,0,$ambiant,0,1,1");
  $updates+= &sendmessage("W","29,$front,40,$back,29,$front,40,$back,1");
  $updates+= &sendmessage("g","DEMOCARS,$soc,$speed,$bearing,0,1,120,$lat,$lon");

  $lastupdated = time if ($updates>0);
  }

my %prevmessages;
sub sendmessage
  {
  my ($code,$data) = @_;

  my $updates = 0;

  my $forceupdate = (($lastupdated==0)||((time-$lastupdated)>=600))?1:0;

  if (($forceupdate)||($appsconnected > 0))
    {
    if ((!defined $prevmessages{$code})||($prevmessages{$code} ne $data)||$forceupdate)
      {
      print STDERR "  Sending $code $data\n";
      $handle->push_write(encode_base64($txcipher->RC4("MP-0 $code$data"),'')."\r\n");
      $prevmessages{$code} = $data;
      $updates++;
      }
    }

  return $updates;
  }

sub getambiant
  {
  print STDERR "  Getting ambiant temperature for Hong Kong\n";
  my $weather = `curl http://rss.weather.gov.hk/rss/CurrentWeather.xml 2>/dev/null`;

  if ($weather =~ /Air temperature.+\s(\d+)\s/)
    {
    $ambiant = $1;
    print "    Ambiant is $ambiant celcius\n";
    }
  $nextambiant = 1800;
  }

