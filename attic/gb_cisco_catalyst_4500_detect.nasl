# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105379");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2015-09-21 13:29:25 +0200 (Mon, 21 Sep 2015)");
  script_name("Cisco Catalyst 4500 Detection (SNMP)");

  script_tag(name:"summary", value:"This VT has been replaced by VT 'Cisco IOS XE Detection (SNMP)' (OID: 1.3.6.1.4.1.25623.1.0.144919).

  This script performs SNMP based detection of Cisco Catalyst 4500.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
