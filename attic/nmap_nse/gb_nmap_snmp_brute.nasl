# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801802");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-01-20 07:52:11 +0100 (Thu, 20 Jan 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Nmap NSE: SNMP Brute");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"Mitigation");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Nmap NSE");

  script_tag(name:"summary", value:"This script attempts to find an SNMP community string by brute force guessing.

  This is a wrapper on the Nmap Security Scanner's snmp-brute.nse.");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
