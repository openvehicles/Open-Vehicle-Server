#!/usr/bin/perl

########################################################################
# OVMS Server Core
#
# This plugin provides the core of the OVMS system, and is always
# automatically loaded.

package OVMS::Server::Core;

use strict;
use warnings;
use Carp;

use AnyEvent;
use AnyEvent::Log;
use Config::IniFiles;
use POSIX qw(strftime);

use Exporter qw(import);

our @EXPORT = qw(
                 MyConfig IsPermitted UTCDate UTCDateFull UTCTime GetVersion
                 ConnStart ConnFinish
                 ConnGetAttribute ConnGetAttributeRef ConnHasAttribute
                 ConnSetAttribute ConnSetAttributes ConnIncAttribute
                 ConnDefined ConnKeys
                 CarConnect CarDisconnect CarConnectionCount CarConnection
                 AppConnect AppDisconnect AppConnectionCount AppConnections
                 BatchConnect BatchDisconnect BatchConnectionCount BatchConnections
                 ClientConnections
                 ConnTransmit CarTransmit ClientsTransmit ConnShutdown
                );

my $VERSION;
if (-e '/usr/bin/git')
  { $VERSION = `/usr/bin/git describe --always --tags --dirty`; chop $VERSION; }
else
  { $VERSION = '3.0.0-custom'; }

my $me;                        # Reference to our singleton object

########################################################################
# Initialisation

use vars qw{
  $config
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

  $self->{'config'} = Config::IniFiles->new(-file => 'conf/ovms_server.conf');
  }

########################################################################
# Server version

sub GetVersion
  {
  return $VERSION;
  }

########################################################################
# Access to configuration object

sub MyConfig
  {
  return $me->{'config'};
  }

########################################################################
# Permissions helpers

sub IsPermitted
  {
  my ($permissions, @rights) = @_;

  return 1 if ($permissions eq '*');

  my %ph = map { lc($_) => 1 } split(/\s*,\s*/,$permissions);

  foreach my $right (@rights)
    {
    return 1 if (defined $ph{lc($right)});
    }

  return 0;
  }

########################################################################
# Date/time helpers

sub UTCDate
  {
  my ($t) = @_;
  $t = time if (!defined $t);

  return strftime "%Y-%m-%d", gmtime($t);
  }

sub UTCDateFull
  {
  my ($t) = @_;
  $t = time if (!defined $t);

  return strftime "%Y-%m-%d 00:00:00", gmtime($t);
  }

sub UTCTime
  {
  my ($t) = @_;
  $t = time if (!defined $t);

  return strftime "%Y-%m-%d %H:%M:%S", gmtime($t);
  }

########################################################################
# Connection Registry

my %conns;                     # Connection informaton (keyed by fd#)

sub ConnStart
  {
  my ($fn, %attr) = @_;

  AE::log info => "#$fn - - ConnStart";

  delete $conns{$fn};          # Clean-up any residual data for this connection

  foreach my $key (keys %attr)
    {
    $conns{$fn}{$key} = $attr{$key};
    }
  }

sub ConnFinish
  {
  my ($fn) = @_;

  AE::log info => "#$fn - - ConnFinish";

  delete $conns{$fn};
  }

sub ConnGetAttribute
  {
  my ($fn, $key) = @_;

  return ((defined $conns{$fn})&&(defined $conns{$fn}{$key}))
         ?$conns{$fn}{$key}
         :undef;
  }

sub ConnGetAttributeRef
  {
  my ($fn, $key) = @_;

  return \$conns{$fn}{$key};
  }

sub ConnHasAttribute
  {
  my ($fn, $key) = @_;

  return ((defined $conns{$fn})&&(defined $conns{$fn}{$key}));
  }

sub ConnSetAttribute
  {
  my ($fn, $key, $value) = @_;

  $conns{$fn}{$key} = $value;
  }

sub ConnSetAttributes
  {
  my ($fn, %attr) = @_;

  foreach my $key (keys %attr)
    {
    $conns{$fn}{$key} = $attr{$key};
    }
  }

sub ConnIncAttribute
  {
  my ($fn, $key, $value) = @_;

  $conns{$fn}{$key} += $value;
  }

sub ConnDefined
  {
  my ($fn) = @_;

  return defined $conns{$fn};
  }

sub ConnKeys
  {
  my ($fn) = @_;

  if (defined $conns{$fn})
    { return keys %{$conns{$fn}}; }
  else
    { return (); }
  }

########################################################################
# Car Connection Registry

my %car_conns;                 # Car connections (vkey -> fd#)

sub CarConnect
  {
  my ($owner, $vehicleid, $fn) = @_;

  my $vkey = $owner . '/' . $vehicleid;
  $car_conns{$vkey} = $fn;

  my $clienttype = $conns{$fn}{'clienttype'};
  AE::log info => "#$fn $clienttype $vkey CarConnect";
  }

sub CarDisconnect
  {
  my ($owner, $vehicleid, $fn) = @_;

  my $vkey = $owner . '/' . $vehicleid;
  my $clienttype = $conns{$fn}{'clienttype'};
  AE::log info => "#$fn $clienttype $vkey CarDisconnect";

  delete $car_conns{$vkey};
  }

sub CarConnectionCount
  {
  my ($owner, $vehicleid) = @_;

  my $vkey = $owner . '/' . $vehicleid;
  return (defined $car_conns{$vkey})?1:0;
  }

sub CarConnection
  {
  my ($owner, $vehicleid) = @_;

  my $vkey = $owner . '/' . $vehicleid;
  return undef if (!defined $car_conns{$vkey});
  return $car_conns{$vkey};
  }

########################################################################
# App Connection Registry

my %app_conns;                 # App connections (vkey{$fd#})

sub AppConnect
  {
  my ($owner, $vehicleid, $fn) = @_;

  my $vkey = $owner . '/' . $vehicleid;
  $app_conns{$vkey}{$fn} = $fn;

  my $clienttype = $conns{$fn}{'clienttype'};
  AE::log info => "#$fn $clienttype $vkey AppConnect";
  }

sub AppDisconnect
  {
  my ($owner, $vehicleid, $fn) = @_;

  my $vkey = $owner . '/' . $vehicleid;
  my $clienttype = $conns{$fn}{'clienttype'};
  AE::log info => "#$fn $clienttype $vkey AppDisconnect";

  delete $app_conns{$vkey}{$fn};
  }

sub AppConnectionCount
  {
  my ($owner, $vehicleid) = @_;

  my $vkey = $owner . '/' . $vehicleid;
  return 0 if (!defined $app_conns{$vkey});
  return scalar keys %{$app_conns{$vkey}};
  }

sub AppConnections
  {
  my ($owner, $vehicleid) = @_;

  my $vkey = $owner . '/' . $vehicleid;
  return () if (!defined $app_conns{$vkey});

  return sort keys %{$app_conns{$vkey}};
  }

########################################################################
# Batch App Connection Registry

my %batch_conns;               # Batch connections (vkey{$fd#})

sub BatchConnect
  {
  my ($owner, $vehicleid, $fn) = @_;

  my $vkey = $owner . '/' . $vehicleid;
  $batch_conns{$vkey}{$fn} = $fn;

  my $clienttype = $conns{$fn}{'clienttype'};
  AE::log info => "#$fn $clienttype $vkey BatchConnect";
  }

sub BatchDisconnect
  {
  my ($owner, $vehicleid, $fn) = @_;

  my $vkey = $owner . '/' . $vehicleid;
  my $clienttype = $conns{$fn}{'clienttype'};
  AE::log info => "#$fn $clienttype $vkey BatchDisconnect";

  delete $batch_conns{$vkey}{$fn};
  }

sub BatchConnectionCount
  {
  my ($owner, $vehicleid) = @_;

  my $vkey = $owner . '/' . $vehicleid;
  return 0 if (!defined $batch_conns{$vkey});
  return scalar keys %{$batch_conns{$vkey}};
  }

sub BatchConnections
  {
  my ($owner, $vehicleid) = @_;

  my $vkey = $owner . '/' . $vehicleid;
  return () if (!defined $batch_conns{$vkey});

  return sort keys %{$batch_conns{$vkey}};
  }

########################################################################
# Batch and App Connection Helpers

sub ClientConnections
  {
  my ($owner, $vehicleid) = @_;

  my $vkey = $owner . '/' . $vehicleid;

  my @clist = ();
  push (@clist, sort keys %{$app_conns{$vkey}}) if (defined $app_conns{$vkey});
  push (@clist, sort keys %{$batch_conns{$vkey}}) if (defined $batch_conns{$vkey});

  return @clist;
  }

########################################################################
# Connection Callback Functions

sub ConnTransmit
  {
  my ($fn, $format, @data) = @_;

  return if (!defined $conns{$fn}{'callback_tx'});

  my $cb = $conns{$fn}{'callback_tx'};
  &$cb($fn, $format, @data);
  }

sub CarTransmit
  {
  my ($owner, $vehicleid, $format, @data) = @_;

  my $vkey = $owner . '/' . $vehicleid;
  if (defined $car_conns{$vkey})
    {
    ConnTransmit($car_conns{$vkey}, $format, @data);
    }
  }

sub ClientsTransmit
  {
  my ($owner, $vehicleid, $format, @data) = @_;

  foreach my $afn (ClientConnections($owner,$vehicleid))
    {
    if (($conns{$afn}{'owner'} ne $owner) ||
        ($conns{$afn}{'vehicleid'} ne $vehicleid))
      {
      my $clienttype = $conns{$afn}{'clienttype'};
      my $vowner = $conns{$afn}{'owner'};
      my $vvehicleid = $conns{$afn}{'vehicleid'};
      AE::log error => "#$afn $clienttype $vkey ClientsTransmit mismatch $vowner/$vvehicleid";
      }
    else
      {
      ConnTransmit($afn, $format, @data);
      }
    }
  }

sub ConnShutdown
  {
  my ($fn) = @_;

  return if (!defined $conns{$fn}{'callback_shutdown'});

  my $cb = $conns{$fn}{'callback_shutdown'};
  &$cb($fn);
  }

1;
