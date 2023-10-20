# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104153");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Nmap NSE net: ntp-monlist");
  script_category(ACT_INIT);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Nmap NSE net");
  script_tag(name:"summary", value:"Obtains and prints an NTP server's monitor data.

Monitor data is a list of the most recently used (MRU) having NTP associations with the target. Each
record contains information about the most recent NTP packet sent by a host to the target including
the source and destination addresses and the NTP version and mode of the packet. With this
information it is possible to classify associated hosts as Servers, Peers, and Clients.

A Peers command is also sent to the target and the peers list in the response allows differentiation
between configured Mode 1 Peers and clients which act like Peers (such as the Windows W32Time
service).

Associated hosts are further classified as either public or private. Private hosts are those having
IP addresses which are not routable on the public Internet and thus can help to form a picture about
the topology of the private network on which the target resides.

Other information revealed by the monlist and peers commands are the host with which the target
clock is synchronized and hosts which send Control Mode (6) and Private Mode (7) commands to the
target and which may be used by admins for the NTP service.

It should be noted that the very nature of the NTP monitor data means that the Mode 7 commands sent
by this script are recorded by the target (and will often appear in these results). Since the
monitor data is a MRU list, it is probable that you can overwrite the record of the Mode 7 command
by sending an innoccuous looking Client Mode request. This can be achieved easily using Nmap:
'nmap -sU -pU:123 -Pn -n --max-retries=0 <target>'

Notes:

  * The monitor list in response to the monlist command is limited to 600 associations.

  * The monitor capability may not be enabled on the target in which case you may receive an error number 4
(No Data Available).

  * There may be a restriction on who can perform Mode 7 commands (e.g. 'restrict
noquery' in 'ntp.conf') in which case you may not receive a reply.

  * This script does not handle authenticating and targets expecting auth info may respond with error number 3 (Format
Error).");

  script_tag(name:"solution_type", value:"Mitigation");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
