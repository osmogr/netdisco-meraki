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

# ────────────────────────────────
# CONFIGURATION
# ────────────────────────────────

my $conf    = setting('meraki');
my $api_key = $conf->{api_key};
my $org_id  = $conf->{org_id};

# API Rate limiting
my $last_request_time = 0;
my $min_interval_usec = 200_000;    # 200ms = 5 requests/sec

# ────────────────────────────────
# API CALLER
# ────────────────────────────────

sub meraki_api {
    my ($path, $retry_count) = @_;
    $retry_count //= 0;

    my $now = time();
    my $delay = $min_interval_usec - (($now - $last_request_time) * 1_000_000);
    usleep($delay) if $delay > 0;
    $last_request_time = time();

    my $url = "https://api.meraki.com/api/v1$path";
    my $http = HTTP::Tiny->new(timeout => 15, verify_SSL => 1);
    my $res = $http->get($url, {
        headers => {
            'X-Cisco-Meraki-API-Key' => $api_key,
            'Accept'                 => 'application/json',
        }
    });

    if ($res->{status} == 429) {
        my $retry_after = $res->{headers}{'retry-after'} || 1;
        warn "[Meraki] Rate limited. Retrying after $retry_after seconds...\n";
        sleep($retry_after);
        die "[Meraki] Exceeded retry limit\n" if $retry_count >= 5;
        return meraki_api($path, $retry_count + 1);
    }

    unless ($res->{success}) {
        warn "[Meraki] API call to $path failed: $res->{status} $res->{reason}\n";
        return;
    }

    return decode_json($res->{content});
}

# ────────────────────────────────
# MAIN WORKER
# ────────────────────────────────

register_worker({ phase => 'main' }, sub {
    print "[Meraki] Starting MerakiSync worker...\n";

    my $dryrun = 0;
    GetOptions('dryrun' => \$dryrun);

    my $networks = meraki_api("/organizations/$org_id/networks");
    die "[Meraki] Failed to fetch networks\n" unless $networks;

    my %switch_ip_for_network;

    foreach my $net (@$networks) {
        my $net_id   = $net->{id};
        my $net_name = $net->{name} || $net_id;

        print "\n[Meraki] Network: $net_name ($net_id)\n";

        # --- Devices sync ---
        try {
            my $devices = meraki_api("/networks/$net_id/devices");
            foreach my $dev (@$devices) {
                my $model = $dev->{model} || '';
                my $device_ip;
                my @extra_vlan_ips = ();

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
                                            last_discover => \'now()',
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

                # Pick first VLAN IP, otherwise fall back to lanIp/wanIp
                $device_ip = $extra_vlan_ips[0] if @extra_vlan_ips;
                $device_ip ||= $dev->{lanIp} || $dev->{wan1Ip} || $dev->{wan2Ip};

                unless ($device_ip) {
                    warn "[WARN] Skipping device $dev->{name} - no usable IP found.\n";
                    next;
                }

                $switch_ip_for_network{$net_id} //= $device_ip;

                if ($dryrun) {
                    print " [DRYRUN] Device: $dev->{name}, IP: $device_ip, Model: $model, FW: $dev->{firmware}\n";
                }
                else {
                    try {
                        schema('netdisco')->resultset('Device')->update_or_create({
                            ip       => $device_ip,
                            dns      => $dev->{name},
                            name     => $dev->{name},
                            model    => $model,
                            vendor   => 'Cisco Meraki',
                            os_ver   => $dev->{firmware},
                            location => $net_name,
                        });
                        print " [+] Synced device $dev->{name} ($device_ip)\n";
                    }
                    catch {
                        warn "[ERROR] Failed to insert Device $dev->{name}: $_\n";
                        next;
                    };

                    # --- Extra VLAN IPs ---
                    foreach my $vlan_ip (@extra_vlan_ips) {
#                        next if $vlan_ip eq $device_ip;
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
                }
            }
        }
        catch {
            warn "[ERROR] Failed to fetch devices for network $net_id: $_\n";
        };

        # --- Clients sync ---
        try {
            my $clients = meraki_api("/networks/$net_id/clients?perPage=1000");
            foreach my $client (@$clients) {
                next unless $client->{mac};
                my $mac = lc $client->{mac};
                my $ip  = $client->{ip} || '';
                my $switch_ip = $switch_ip_for_network{$net_id} || next;
                my $port = 'Meraki Port';

                if ($dryrun) {
                    print " [DRYRUN] MAC: $mac, IP: $ip, Switch: $switch_ip, Port: $port\n";
                    next;
                }

                try {
                    schema('netdisco')->resultset('Node')->update_or_create({
                        mac         => $mac,
                        switch      => $switch_ip,
                        port        => $port,
                        vlan        => undef,
                        active      => 'true',
                        time_first  => \'now()',
                        time_recent => \'now()',
                        time_last   => \'now()',
                    });
                }
                catch {
                    warn "[ERROR] Failed to insert Node $mac: $_\n";
                };

                if ($ip =~ /^(\d{1,3}\.){3}\d{1,3}$/) {
                    try {
                        schema('netdisco')->resultset('NodeIp')->update_or_create({
                            mac        => $mac,
                            ip         => $ip,
                            active     => 'true',
                            time_first => \'now()',
                            time_last  => \'now()',
                        });
                    }
                    catch {
                        warn "[ERROR] Failed to insert NodeIp $ip for $mac: $_\n";
                    };
                }
            }
        }
        catch {
            warn "[ERROR] Failed to fetch clients for network $net_id: $_\n";
        };
    }

    print "\n[Meraki] Sync complete\n";
    return Status->done("MerakiSync: Work Finished");
});

true;
