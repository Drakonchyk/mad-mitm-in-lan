@load base/frameworks/notice
@load base/packet-protocols/ethernet
@load base/packet-protocols/icmp
@load base/protocols/dhcp
@load policy/misc/stats
@load policy/tuning/json-logs

redef Stats::report_interval = 2sec;

module MITMLab;

export {
    redef enum Notice::Type += {
        ARP_Spoof,
        ICMP_Redirect,
        DNS_Spoof,
        DHCP_Spoof,
    };

    const gateway_ip: addr = __GATEWAY_IP__ &redef;
    const lab_subnet: subnet = __LAB_SUBNET__ &redef;
    const dns_server: addr = __DNS_SERVER__ &redef;
    const attacker_ip: addr = __ATTACKER_IP__ &redef;
    const victim_ip: addr = __VICTIM_IP__ &redef;
    const attacker_mac: string = "__ATTACKER_MAC__" &redef;
    const victim_mac: string = "__VICTIM_MAC__" &redef;
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

event dhcp_message(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options)
    {
    local msg_type = DHCP::message_types[msg$m_type];

    if ( msg$op != 2 )
        return;

    if ( msg$m_type != 2 && msg$m_type != 5 )
        return;

    local server = msg$siaddr;

    if ( server == 0.0.0.0 )
        {
        if ( c$id$orig_h == attacker_ip || c$id$orig_h == gateway_ip )
            server = c$id$orig_h;
        else if ( c$id$resp_h == attacker_ip || c$id$resp_h == gateway_ip )
            server = c$id$resp_h;
        }

    if ( server == gateway_ip )
        return;

    if ( server !in lab_subnet )
        return;

    NOTICE([$note=DHCP_Spoof,
            $msg=fmt("Rogue DHCP %s from non-gateway server IP %s assigned %s", msg_type, server, msg$yiaddr),
            $sub=fmt("dhcp_type=%s yiaddr=%s siaddr=%s chaddr=%s xid=%s", msg_type, msg$yiaddr, msg$siaddr, msg$chaddr, msg$xid),
            $src=server,
            $dst=victim_ip]);
    }
