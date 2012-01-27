#!/usr/bin/perl

use strict;
use SNMP::Extension::PassPersist;

my $base = ".1.3.6.1.4.1.39178.100.1.1.1.2";

my $extsnmp = SNMP::Extension::PassPersist->new(
    backend_collect => \&update_tree
    );
$extsnmp->run;


sub update_tree {
    my ($self) = @_;

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
            # Append to our tree
            $extsnmp->add_oid_entry($oid, "counter", $value);
        }
        close(ETHTOOL);
    }
}
