package App::NetdiscoX::Worker::Plugin::MerakiSync;

use strict;
use warnings;
use Dancer ':script';
use App::Netdisco::Worker::Plugin;
use aliased 'App::Netdisco::Worker::Status';

use Dancer::Plugin::DBIC 'schema';
use HTTP::Tiny;
use JSON qw(decode_json);
use Try::Tiny;
use Time::HiRes qw(usleep time);
use Encode qw(encode);
use Getopt::Long;
use List::Util qw(uniq);

# ────────────────────────────────
# CONFIGURATION
# ────────────────────────────────

my $conf    = setting('meraki');
my $api_key = $conf->{api_key};
my $org_id  = $conf->{org_id};

# API Rate limiting - Meraki allows 10 requests/sec, we use 8 for safety
my $last_request_time = 0;
my $min_interval_usec = 125_000;    # 125ms = 8 requests/sec

# Cache for API responses (keyed by path, expires after 60 seconds)
my %api_cache;
my $cache_ttl = 60;

# ────────────────────────────────
# API CALLER WITH CACHING
# ────────────────────────────────

sub meraki_api {
    my ($path, $retry_count, $no_cache) = @_;
    $retry_count //= 0;
    $no_cache    //= 0;

    # Check cache first unless disabled
    if (!$no_cache && exists $api_cache{$path}) {
        my $cached = $api_cache{$path};
        if (time() - $cached->{timestamp} < $cache_ttl) {
            return $cached->{data};
        }
        delete $api_cache{$path};  # Expired
    }

    # Rate limiting
    my $now = time();
    my $delay = $min_interval_usec - (($now - $last_request_time) * 1_000_000);
    usleep($delay) if $delay > 0;
    $last_request_time = time();

    my $url = "https://api.meraki.com/api/v1$path";
    my $http = HTTP::Tiny->new(timeout => 30, verify_SSL => 1);  # Increased timeout
    my $res = $http->get($url, {
        headers => {
            'X-Cisco-Meraki-API-Key' => $api_key,
            'Accept'                 => 'application/json',
        }
    });

    # Handle rate limiting with exponential backoff
    if ($res->{status} == 429) {
        my $retry_after = $res->{headers}{'retry-after'} || (2 ** $retry_count);
        warn "[Meraki] Rate limited on $path. Retrying after $retry_after seconds...\n";
        sleep($retry_after);
        die "[Meraki] Exceeded retry limit on $path\n" if $retry_count >= 5;
        return meraki_api($path, $retry_count + 1, $no_cache);
    }

    # Handle server errors with retry
    if ($res->{status} >= 500 && $retry_count < 3) {
        warn "[Meraki] Server error $res->{status} on $path. Retrying...\n";
        sleep(2 ** $retry_count);
        return meraki_api($path, $retry_count + 1, $no_cache);
    }

    unless ($res->{success}) {
        warn "[Meraki] API call to $path failed: $res->{status} $res->{reason}\n";
        return;
    }

    my $data = decode_json($res->{content});
    
    # Cache the response
    $api_cache{$path} = {
        data      => $data,
        timestamp => time(),
    } unless $no_cache;

    return $data;
}

# ────────────────────────────────
# BULK DATABASE OPERATIONS
# ────────────────────────────────

sub bulk_insert_nodes {
    my ($nodes_data) = @_;
    return unless @$nodes_data;

    my $schema = schema('netdisco');
    try {
        $schema->txn_do(sub {
            foreach my $node (@$nodes_data) {
                $schema->resultset('Node')->update_or_create($node);
            }
        });
    }
    catch {
        warn "[ERROR] Bulk node insert failed: $_\n";
    };
}

sub bulk_insert_node_ips {
    my ($ips_data) = @_;
    return unless @$ips_data;

    my $schema = schema('netdisco');
    try {
        $schema->txn_do(sub {
            foreach my $ip_data (@$ips_data) {
                $schema->resultset('NodeIp')->update_or_create($ip_data);
            }
        });
    }
    catch {
        warn "[ERROR] Bulk NodeIp insert failed: $_\n";
    };
}

# ────────────────────────────────
# TOPOLOGY BUILDER (LLDP/CDP)
# ────────────────────────────────

sub sync_device_topology {
    my ($device_ip, $serial, $net_id, $dryrun) = @_;
    
    return unless $device_ip && $serial;

    # Get LLDP/CDP neighbors
    my $lldp_cdp = meraki_api("/devices/$serial/lldp_cdp");
    return unless $lldp_cdp && ref $lldp_cdp eq 'HASH';

    my $ports = $lldp_cdp->{ports} || {};
    
    foreach my $port_num (keys %$ports) {
        my $port_data = $ports->{$port_num};
        next unless $port_data && ref $port_data eq 'HASH';

        my $cdp = $port_data->{cdp};
        my $lldp = $port_data->{lldp};

        my $neighbor_data;
        
        if ($cdp && ref $cdp eq 'HASH') {
            $neighbor_data = {
                platform     => $cdp->{platform},
                device_id    => $cdp->{deviceId},
                port_id      => $cdp->{portId},
                system_name  => $cdp->{deviceId},
                capabilities => $cdp->{capabilities},
            };
        }
        elsif ($lldp && ref $lldp eq 'HASH') {
            $neighbor_data = {
                platform     => $lldp->{systemDescription},
                device_id    => $lldp->{chassisId},
                port_id      => $lldp->{portId},
                system_name  => $lldp->{systemName},
                capabilities => $lldp->{systemCapabilities},
            };
        }

        next unless $neighbor_data;

        if ($dryrun) {
            print "   [DRYRUN] Topology: Port $port_num -> $neighbor_data->{system_name} ($neighbor_data->{port_id})\n";
            next;
        }

        try {
            schema('netdisco')->resultset('DevicePort')->update_or_create({
                ip               => $device_ip,
                port             => $port_num,
                remote_id        => $neighbor_data->{device_id},
                remote_port      => $neighbor_data->{port_id},
                remote_type      => $neighbor_data->{platform},
                is_uplink        => ($neighbor_data->{capabilities} =~ /router/i ? 'true' : 'false'),
            });
        }
        catch {
            warn "[ERROR] Failed to insert topology for $device_ip port $port_num: $_\n";
        };
    }
}

# ────────────────────────────────
# ENHANCED DEVICE SYNC
# ────────────────────────────────

sub sync_device_full {
    my ($dev, $net_id, $net_name, $dryrun) = @_;
    
    my $model = $dev->{model} || '';
    my $serial = $dev->{serial};
    my $device_ip;
    my @extra_vlan_ips = ();
    my %device_data;

    # Pull VLAN IPs for MX/Z
    if ($model =~ /^(MX|Z)/i) {
        try {
            my $vlan_info = meraki_api("/networks/$net_id/appliance/vlans");
            if ($vlan_info && ref $vlan_info eq 'ARRAY') {
                foreach my $vlan (@$vlan_info) {
                    if ($vlan->{applianceIp}) {
                        push @extra_vlan_ips, $vlan->{applianceIp};
                        if (!$dryrun) {
                            schema('netdisco')->resultset('DeviceVlan')->update_or_create({
                                ip            => $vlan->{applianceIp},
                                vlan          => $vlan->{id},
                                description   => $vlan->{name} || $vlan->{subnet},
                                last_discover => \['now()'],
                            });
                        }
                    }
                }
            }
        }
        catch {
            warn "[Meraki] VLAN query failed for $dev->{name}: $_\n";
        };
    }

    # Get management interface details
    if ($serial && $model =~ /^MS/i) {  # Switches have management interfaces
        try {
            my $mgmt = meraki_api("/devices/$serial/managementInterface");
            if ($mgmt && $mgmt->{wan1} && $mgmt->{wan1}->{staticIp}) {
                $device_ip = $mgmt->{wan1}->{staticIp};
            }
        }
        catch {
            warn "[Meraki] Management interface query failed for $dev->{name}: $_\n";
        };
    }

    # Pick first VLAN IP, otherwise fall back to lanIp/wanIp
    $device_ip ||= $extra_vlan_ips[0] if @extra_vlan_ips;
    $device_ip ||= $dev->{lanIp} || $dev->{wan1Ip} || $dev->{wan2Ip};

    unless ($device_ip) {
        warn "[WARN] Skipping device $dev->{name} - no usable IP found.\n";
        return;
    }

    # Get uplink information
    my $uplink_status;
    if ($serial) {
        try {
            $uplink_status = meraki_api("/devices/$serial/uplinks/statuses");
        }
        catch {
            warn "[Meraki] Uplink status query failed for $dev->{name}: $_\n";
        };
    }

    # Build comprehensive device data
    %device_data = (
        ip          => $device_ip,
        dns         => $dev->{name},
        name        => $dev->{name},
        model       => $model,
        vendor      => 'Cisco Meraki',
        os_ver      => $dev->{firmware},
        location    => $net_name,
        serial      => $serial,
        mac         => $dev->{mac},
        contact     => $dev->{tags} ? join(',', @{$dev->{tags}}) : undef,
        uptime      => undef,  # Meraki doesn't expose uptime directly
        last_discover => \['now()'],
    );

    if ($dryrun) {
        print " [DRYRUN] Device: $dev->{name}, IP: $device_ip, Model: $model, FW: $dev->{firmware}, Serial: $serial\n";
        if ($uplink_status && ref $uplink_status eq 'ARRAY') {
            foreach my $uplink (@$uplink_status) {
                print "   [DRYRUN] Uplink: $uplink->{interface} - Status: $uplink->{status}\n";
            }
        }
        return $device_ip;
    }

    try {
        schema('netdisco')->resultset('Device')->update_or_create(\%device_data);
        print " [+] Synced device $dev->{name} ($device_ip)\n";
    }
    catch {
        warn "[ERROR] Failed to insert Device $dev->{name}: $_\n";
        return;
    };

    # Add extra VLAN IPs to DeviceIp table
    foreach my $vlan_ip (@extra_vlan_ips) {
        next unless $vlan_ip =~ /^(\d{1,3}\.){3}\d{1,3}$/;

        try {
            schema('netdisco')->resultset('DeviceIp')->find_or_create({
                ip    => $device_ip,
                alias => $vlan_ip,
                dns   => $dev->{name},
                port  => undef,
            });
            print "   [+] Added VLAN IP to DeviceIp: $vlan_ip\n";
        }
        catch {
            warn "[ERROR] Failed to insert DeviceIp $vlan_ip: $_\n";
        };
    }

    # Sync topology for MS switches
    if ($model =~ /^MS/i && $serial) {
        sync_device_topology($device_ip, $serial, $net_id, $dryrun);
    }

    return $device_ip;
}

# ────────────────────────────────
# ENHANCED CLIENT SYNC
# ────────────────────────────────

sub sync_clients_enhanced {
    my ($net_id, $net_name, $switch_ip, $dryrun) = @_;
    
    my $clients = meraki_api("/networks/$net_id/clients?perPage=1000&timespan=86400");  # Last 24 hours
    return unless $clients && ref $clients eq 'ARRAY';

    my @nodes_batch;
    my @ips_batch;

    foreach my $client (@$clients) {
        next unless $client->{mac};
        my $mac = lc $client->{mac};
        my $ip  = $client->{ip} || '';
        
        # Enhanced port/VLAN information
        my $port = $client->{switchport} || 'Meraki Port';
        my $vlan = $client->{vlan};
        my $ssid = $client->{ssid};  # For wireless clients
        my $description = $client->{description} || $client->{dhcpHostname} || '';

        # Determine the actual switch IP if available
        my $actual_switch = $switch_ip;
        if ($client->{recentDeviceSerial}) {
            # Try to look up the device IP by serial if we have it cached
            # For now, use the network's primary switch
            $actual_switch = $switch_ip;
        }

        if ($dryrun) {
            print " [DRYRUN] MAC: $mac, IP: $ip, Switch: $actual_switch, Port: $port, VLAN: $vlan, SSID: $ssid\n";
            next;
        }

        # Build node data
        my $node_data = {
            mac         => $mac,
            switch      => $actual_switch,
            port        => $port,
            vlan        => $vlan,
            active      => 'true',
            time_first  => \['now()'],
            time_recent => \['now()'],
            time_last   => \['now()'],
        };
        push @nodes_batch, $node_data;

        # Build IP data
        if ($ip =~ /^(\d{1,3}\.){3}\d{1,3}$/) {
            my $ip_data = {
                mac        => $mac,
                ip         => $ip,
                active     => 'true',
                time_first => \['now()'],
                time_last  => \['now()'],
            };
            push @ips_batch, $ip_data;
        }

        # Batch insert every 100 records
        if (@nodes_batch >= 100) {
            bulk_insert_nodes(\@nodes_batch);
            @nodes_batch = ();
        }
        if (@ips_batch >= 100) {
            bulk_insert_node_ips(\@ips_batch);
            @ips_batch = ();
        }
    }

    # Insert remaining records
    bulk_insert_nodes(\@nodes_batch) if @nodes_batch;
    bulk_insert_node_ips(\@ips_batch) if @ips_batch;

    print "   [+] Synced " . scalar(@$clients) . " clients\n";
}

# ────────────────────────────────
# MAIN WORKER
# ────────────────────────────────

register_worker({ phase => 'main' }, sub {
    print "[Meraki] Starting MerakiSync worker...\n";

    my $dryrun = 0;
    my $devices_only = 0;
    my $clients_only = 0;
    my $topology_only = 0;
    
    GetOptions(
        'dryrun'        => \$dryrun,
        'devices-only'  => \$devices_only,
        'clients-only'  => \$clients_only,
        'topology-only' => \$topology_only,
    );

    my $networks = meraki_api("/organizations/$org_id/networks");
    die "[Meraki] Failed to fetch networks\n" unless $networks;

    my %switch_ip_for_network;
    my $total_devices = 0;
    my $total_clients = 0;

    foreach my $net (@$networks) {
        my $net_id   = $net->{id};
        my $net_name = $net->{name} || $net_id;

        print "\n[Meraki] Network: $net_name ($net_id)\n";

        # --- Devices sync ---
        unless ($clients_only) {
            try {
                my $devices = meraki_api("/networks/$net_id/devices");
                foreach my $dev (@$devices) {
                    my $device_ip = sync_device_full($dev, $net_id, $net_name, $dryrun);
                    $switch_ip_for_network{$net_id} //= $device_ip if $device_ip;
                    $total_devices++;
                }
            }
            catch {
                warn "[ERROR] Failed to fetch devices for network $net_id: $_\n";
            };
        }

        # --- Clients sync ---
        unless ($devices_only || $topology_only) {
            my $switch_ip = $switch_ip_for_network{$net_id};
            if ($switch_ip) {
                try {
                    sync_clients_enhanced($net_id, $net_name, $switch_ip, $dryrun);
                    $total_clients++;
                }
                catch {
                    warn "[ERROR] Failed to fetch clients for network $net_id: $_\n";
                };
            }
            else {
                warn "[WARN] No switch IP found for network $net_name, skipping client sync\n";
            }
        }
    }

    print "\n[Meraki] Sync complete: $total_devices devices processed";
    print ", $total_clients client networks processed" unless $devices_only;
    print "\n";
    
    return Status->done("MerakiSync: Work Finished");
});

true;
