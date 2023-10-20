# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104011");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_name("Nmap NSE net: snmp-interfaces");
  script_category(ACT_INIT);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Nmap NSE net");

  script_tag(name:"summary", value:"Attempts to enumerate network interfaces through SNMP.

This script can also be run during Nmap's pre-scanning phase and can attempt to add the SNMP
server's interface addresses to the target list.  The script argument 'snmp-
interfaces.host' is required to know what host to probe.  To specify a port for the SNMP
server other than 161, use 'snmp-interfaces.port'.  When run in this way, the script's
output tells how many new targets were successfully added.

SYNTAX:

snmp-interfaces.port:   The optional port number corresponding
to the host script argument.  Defaults to 161.

snmpcommunity:  The community string to use. If not given, it is
''public'', or whatever is passed to 'buildPacket'.

snmp-interfaces.host:   Specifies the SNMP server to probe when
running in the 'pre-scanning phase'.");

  script_tag(name:"solution_type", value:"Mitigation");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
