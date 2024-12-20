# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105461");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-11-20 12:46:40 +0100 (Fri, 20 Nov 2015)");
  script_name("Cisco Mobility Service Engine Web Interface Detection");

  script_tag(name:"summary", value:"This script performs HTTP(s) based detection of Cisco Mobility Service Engine");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

# 10.x
url = '/api/config/v1/version/image';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "cmx_image_version" >< buf && "cmx_rpm_versions" >< buf )
{
  # Example response: {"cmx_image_version":"CISCO_CMX-10.3.0-beta.202.cmx","cmx_rpm_versions":["cisco_cmx-10.3.0-beta.202","cisco_cmx_connect-10.2.0-530","cisco_cmx_wips-10.2.0-96"]}
  # "cmxctl version" reported 10.2.0-96, so i use "cisco_cmx_wips-rpm-version" instead of cmx_image_version as version
  version = eregmatch( pattern:'cisco_cmx_wips-([^"]+)', string:buf );
  if( ! isnull( version[1] ) )
  {
    set_kb_item( name:"cisco_mse/http/version", value:version[1] );
    set_kb_item( name:"cisco_mse/lsc", value:TRUE );
    report = 'Cisco Mobility Service Engine Web Interface is running at this port\nVersion: ' + version[1] + '\nCPE: cpe:/a:cisco:mobility_services_engine:' + version[1];
    log_message( port:port, data:report);
    exit( 0 );
  }
}

# < 10.x
# seems not possible to get the version without auth
url = '/mseui/';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "<title>Sign in - Cisco MSE</title>" >< buf )
{
  report = 'Cisco Mobility Service Engine Web Interface is running at this port\nCPE: cpe:/a:cisco:mobility_services_engine';
  log_message( port:port, data:report);
  exit( 0 );
}

exit( 0 );
