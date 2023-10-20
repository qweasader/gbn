# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103317");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2011-11-11 10:17:05 +0100 (Fri, 11 Nov 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Dell KACE K2000 Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2011 Greenbone AG");

  script_tag(name:"summary", value:"Detection of Dell KACE.

  The script sends a connection request to the server and attempts to extract the version number from the reply.

  This VT has been replaced by VT 'Quest KACE Systems Management Appliance (SMA) Detection'
  (OID: 1.3.6.1.4.1.25623.1.0.141135).");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"deprecated", value: TRUE);

  exit(0);
}

exit(66);
