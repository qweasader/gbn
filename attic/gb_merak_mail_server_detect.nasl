# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800096");
  script_version("2024-04-04T05:05:25+0000");
  script_tag(name:"last_modification", value:"2024-04-04 05:05:25 +0000 (Thu, 04 Apr 2024)");
  script_tag(name:"creation_date", value:"2009-06-02 09:27:25 +0200 (Tue, 02 Jun 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Merak Mail Server Web Mail Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");

  script_tag(name:"summary", value:"HTTP based detection of Merak Mail Server.

  This VT has been replaced by the VT 'IceWarp Mail Server Detection Consolidation'
  (OID: 1.3.6.1.4.1.25623.1.0.140330) and related additional detection VTs.");

  script_tag(name:"deprecated", value:TRUE);

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

exit(66);
