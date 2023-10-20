# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105328");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-08-21 14:51:09 +0200 (Fri, 21 Aug 2015)");
  script_name("pfSense Detection (SSH)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("pfsense/uname");

  script_tag(name:"summary", value:"This script performs SSH based detection of pfSense.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("host_details.inc");

uname = get_kb_item( "pfsense/uname" );
if( ! uname || "pfSense" >!< uname )
  exit( 0 );

port = get_kb_item( "pfsense/ssh/port" );

set_kb_item( name:"pfsense/installed", value:TRUE );
set_kb_item( name:"pfsense/ssh/installed", value:TRUE );

vers = 'unknown';

# *** Welcome to pfSense 2.4.4-RELEASE-p3 (amd64) on pfSense ***
# *** Welcome to pfSense 2.4.2-RELEASE (amd64) on pfSense ***
version = eregmatch( pattern:'Welcome to pfSense ([^-]+)-RELEASE-?(p[0-9]+)?', string:uname );
if( ! isnull( version[1] ) ) {
  set_kb_item( name:"pfsense/ssh/" + port + "/version", value:version[1] );
  set_kb_item( name:"pfsense/ssh/" + port + "/concluded", value:uname );
  if( ! isnull( version[2] ) )
    set_kb_item( name:"pfsense/ssh/" + port + "/patch", value:version[2] );
}

exit( 0 );