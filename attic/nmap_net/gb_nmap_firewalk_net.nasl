# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104048");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Nmap NSE net: firewalk");
  script_category(ACT_INIT);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2011 NSE-Script: Greenbone AG");
  script_family("Nmap NSE net");

  script_tag(name:"summary", value:"Tries to discover firewall rules using an IP TTL expiration technique known as firewalking.

The scan requires a firewall (or 'gateway') and a metric (or 'target'). For each filtered port on
the target, send a probe with an IP TTL one greater than the number of hops to the gateway. The TTL
can be given in two ways: directly with the 'firewalk.ttl' script argument, or indirectly
with the 'firewalk.gateway' script argument. For 'firewalk.gateway', Nmap must
be run with the '--traceroute' option and the gateway must appear as one of the
traceroute hops.

If the probe is forwarded by the gateway, then we can expect to receive an ICMP_TIME_EXCEEDED reply
from the gateway next hop router, or eventually the target if it is directly connected to the
gateway. Otherwise, the probe will timeout. As for UDP scans, this process can be quite slow if lots
of ports are blocked by the gateway.

From an original idea of M. Schiffman and D. Goldsmith, authors of the firewalk tool.

SYNTAX:

firewalk.ttl:  value of the TTL to use. Should be one greater than the
number of hops to the gateway. In case both 'firewalk.ttl' and
'firewalk.gateway' IP address are
supplied, 'firewalk.gateway' is ignored.



firewalk.gateway:  IP address of the tested firewall. Must be present in the traceroute results.");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
