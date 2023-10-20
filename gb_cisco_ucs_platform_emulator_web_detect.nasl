# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = 'cpe:/a:cisco:unified_computing_system_software';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105799");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-07-07 10:40:45 +0200 (Thu, 07 Jul 2016)");
  script_name("Cisco UCS Platform Emulator Detection");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_cisco_ucs_manager_detect.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("cisco_ucs_manager/installed");

  script_tag(name:"summary", value:"This script performs HTTP based detection of Cisco UCS Platform Emulator");
  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

buf = http_get_cache( port:port, item:'/' );

if( "<title>Cisco UCS Manager</title>" >!< buf || "Cisco UCS Platform Emulator" >!< buf ) exit( 0 );

vers = 'unknown';
cpe = 'cpe:/a:cisco:unified_computing_system_platform_emulator';

version = eregmatch( pattern:'Cisco UCS Platform Emulator (([0-9.]+\\([^)]+\\))\\(([0-9][^)]+)\\))', string:buf );

if( ! isnull(version[2] ) )
{
  vers = version[2];
  cpe += ':' + vers;
  set_kb_item( name:'cisco_ucs_plattform_emulator/version', value:vers);
}

if( ! isnull(version[3] ) )
{
  build = version[3];
  set_kb_item( name:'cisco_ucs_plattform_emulator/build', value:build);
}

set_kb_item( name:"cisco_ucs_plattform_emulator/installed",value:TRUE );

register_product( cpe:cpe, location:"/", port:port );

log_message( data: build_detection_report( app:"Cisco UCS Platform Emulator", version:vers, install:"/", cpe:cpe, concluded: version[0] ),
             port:port);

exit(0);
