# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104105");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-06-01 16:32:46 +0200 (Wed, 01 Jun 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Nmap NSE net: ntp-info");
  script_category(ACT_INIT);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Nmap NSE net");

  script_xref(name:"URL", value:"http://www.eecis.udel.edu/~mills/database/reports/ntp4/ntp4.pdf");

  script_tag(name:"summary", value:"Gets the time and configuration variables from an NTP server. We send two requests: a time request
and a 'read variables' (opcode 2) control message. Without verbosity, the script shows the time and
the value of the 'version', 'processor', 'system',
'refid', and 'stratum' variables. With verbosity, all variables are shown.

See RFC 1035 and the Network Time Protocol Version 4 Reference and Implementation Guide
(see the references) for documentation of the protocol.");

  script_tag(name:"solution_type", value:"Mitigation");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
