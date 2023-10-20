# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105411");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-10-19 11:11:38 +0200 (Mon, 19 Oct 2015)");
  script_name("Junos Space Web-UI Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of the Junos Space Web-UI.");

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
include("host_details.inc");

port = http_get_port( default:443 );

url = "/mainui/";
buf = http_get_cache( item:url, port:port );

if( "Junos Space Login</title>" >!< buf || "j_username" >!< buf ) exit( 0 );

set_kb_item( name:"junos_space_webui/installed", value:TRUE );
set_kb_item( name:"junos_space_webui/detected", value:TRUE );
set_kb_item( name:"junos_space_webui/http/detected", value:TRUE );
register_product( cpe:"cpe:/a:juniper:junos_space", location:url, port:port, service:"www" );

log_message( data:'The Junos Space Web-UI is running at this port.\nCPE: cpe:/a:juniper:junos_space',  port:port );

exit( 0 );
