# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812003");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2017-10-03 16:38:14 +0530 (Tue, 03 Oct 2017)");
  script_name("Cisco Small Business 500 Series Stackable Managed Switches Detection (SNMP)");

  script_tag(name:"summary", value:"This script performs SNMP based detection of
  Cisco Small Business 500 Series Stackable Managed Switches.

  This VT has been replaced by VT 'Cisco Small Business Switch Detection (SNMP)' (OID: 1.3.6.1.4.1.25623.1.0.144401).");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone AG");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
