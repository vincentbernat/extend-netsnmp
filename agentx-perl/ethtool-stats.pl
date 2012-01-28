#!/usr/bin/env perl

use strict;
use NetSNMP::OID;
use NetSNMP::ASN (':all');
use NetSNMP::agent (':all');

my %cache = ();			# Cache
my @cache_oids = ();		# Keys, sorted
my $cache_updated = 0;
my $base = ".1.3.6.1.4.1.39178.100.1.1.1.2";

# Update cache
sub update_stats {
    return if time() - $cache_updated < 30;
    %cache = ();

    # We grab interfaces from /sys/class/net
    my @interfaces = </sys/class/net/*>;
    foreach my $interface (@interfaces) {
	# Get index of this interface
	open(IFINDEX, "$interface/ifindex") or next;
	my $index = int(<IFINDEX>);
	close(IFINDEX);
	
	# Call ethtool
	$interface =~ s/^.*\///;
	open(ETHTOOL, "ethtool -S $interface 2>/dev/null |") or next;
	while (<ETHTOOL>) {
	    # Extract name and value
	    /^\s+(\w+): (\d+)$/ or next;
	    my $name = $1;
	    my $value = int($2);
	    # Compute OID
	    my $oid = "$base.$index";
	    foreach my $char (split //, $name) {
		$oid .= ".";
		$oid .= ord($char);
	    }
	    # Put in the cache
	    $cache{$oid} = $value;
	}
	close(ETHTOOL);
    }
    @cache_oids = sort { new NetSNMP::OID($a) <=> new NetSNMP::OID($b) } (keys %cache);
    $cache_updated = time();
}

# Handle request
sub handle_stats {
    my ($handler, $registration_info, $request_info, $requests) = @_;
    update_stats;		# Maybe we should do this in a thread...
    for (my $request = $requests; $request; $request = $request->next()) {
	$SNMP::use_numeric = 1;
	my $oid = $request->getOID();
	my $noid=SNMP::translateObj($oid);
	if ($request_info->getMode() == MODE_GET) {
	    # For a GET request, we just check the cache
	    if (exists $cache{$noid}) {
		$request->setValue(ASN_COUNTER64, $cache{$noid});
	    }
	} elsif ($request_info->getMode() == MODE_GETNEXT) {
	    # For a GETNEXT, we need to find a best match. This is the
	    # first match strictly superior to the requested OID.
	    my $bestoid = undef;
	    foreach my $currentoid (@cache_oids) {
		$currentoid = new NetSNMP::OID($currentoid);
		next if $currentoid <= $oid;
		$bestoid = $currentoid;
		last;
	    }
	    if (defined $bestoid) {
		$SNMP::use_numeric = 1;
		my $noid=SNMP::translateObj($bestoid);
		$request->setOID($bestoid);
		$request->setValue(ASN_COUNTER64, $cache{$noid});
	    }
	}
    }
}

my $agent = new NetSNMP::agent(
    'Name' => "ethtool",
    'AgentX' => 1);

# Register MIB
$agent->register("ethtool-stats", $base,
		 \&handle_stats) or die "registration of handler failed!\n";

# Main loop
$SIG{'INT'} = \&shutdown;
$SIG{'QUIT'} = \&shutdown;
my $running = 1;
while ($running) {
    $agent->agent_check_and_process(1);
}
$agent->shutdown();

sub shutdown {
    # Shutdown requested
    $running = 0;
}
