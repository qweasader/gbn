# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803559");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-02-28 19:00:48 +0530 (Thu, 28 Feb 2013)");
  script_name("Nmap NSE 6.01: ntp-info");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Nmap NSE");

  script_xref(name:"URL", value:"http://www.eecis.udel.edu/~mills/database/reports/ntp4/ntp4.pdf");

  script_tag(name:"summary", value:"Gets the time and configuration variables from an NTP server. We send two requests: a time request
and a 'read variables' (opcode 2) control message. Without verbosity, the script shows the time and
the value of the 'version', 'processor', 'system',
'refid', and 'stratum' variables. With verbosity, all variables are shown.

See RFC 1035 and the Network Time Protocol Version 4 Reference and Implementation Guide
for documentation of the protocol (see references).");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
