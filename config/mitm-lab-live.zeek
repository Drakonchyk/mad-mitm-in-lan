@load base/frameworks/notice
@load base/packet-protocols/ethernet
@load base/packet-protocols/icmp
@load policy/tuning/json-logs

module MITMLab;

export {
    redef enum Notice::Type += {
        ARP_Spoof,
        ICMP_Redirect,
        DNS_Spoof,
    };

    const gateway_ip: addr = __GATEWAY_IP__ &redef;
    const dns_server: addr = __DNS_SERVER__ &redef;
    const attacker_ip: addr = __ATTACKER_IP__ &redef;
    const victim_ip: addr = __VICTIM_IP__ &redef;
    const attacker_mac: string = "__ATTACKER_MAC__" &redef;
    const gateway_mac: string = "__GATEWAY_MAC__" &redef;
    const monitored_domains: set[string] = { __ZEEK_DOMAIN_SET__ } &redef;
}

event zeek_init() &priority=10
    {
    PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, 0x0806, PacketAnalyzer::ANALYZER_ARP);
    PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, 0x8035, PacketAnalyzer::ANALYZER_ARP);
    }

event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
    {
    if ( SPA != gateway_ip )
        return;

    if ( TPA != victim_ip )
        return;

    if ( to_lower(SHA) != to_lower(attacker_mac) )
        return;

    NOTICE([$note=ARP_Spoof,
            $msg=fmt("Gateway ARP reply claimed by attacker MAC %s", SHA),
            $sub=fmt("spa=%s sha=%s tpa=%s tha=%s", SPA, SHA, TPA, THA),
            $src=attacker_ip,
            $dst=victim_ip]);
    }

event icmp_sent(c: connection, info: icmp_info)
    {
    # Zeek 8.1.1 sees these IPv4 redirects through icmp_sent() on this trace.
    if ( c$id$orig_p != 5/icmp )
        return;

    if ( c$id$orig_h != attacker_ip )
        return;

    if ( c$id$resp_h != victim_ip )
        return;

    NOTICE([$note=ICMP_Redirect,
            $msg=fmt("ICMP redirect from %s to %s", c$id$orig_h, c$id$resp_h),
            $sub=fmt("icmp_type=%s icmp_code=%s", c$id$orig_p, c$id$resp_p),
            $src=c$id$orig_h,
            $dst=c$id$resp_h]);
    }

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
    {
    local query = to_lower(ans$query);

    if ( c$id$orig_h != victim_ip )
        return;

    if ( c$id$resp_h != dns_server )
        return;

    if ( query !in monitored_domains )
        return;

    if ( a != attacker_ip )
        return;

    NOTICE([$note=DNS_Spoof,
            $msg=fmt("DNS answer for %s points to attacker IP %s", query, a),
            $sub=fmt("query=%s answer=%s", query, a),
            $src=c$id$resp_h,
            $dst=c$id$orig_h]);
    }
