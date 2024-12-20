# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:outlook_web_app";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105151");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-12-22 14:36:28 +0100 (Mon, 22 Dec 2014)");
  script_name("SafeNet SAS OWA Agent Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_owa_detect.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("ms/owa/installed");

  script_tag(name:"summary", value:"The script sends a connection request to the server and
  attempts to detect SafeNet SAS OWA Agent from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! http_can_host_asp( port:port ) )
  exit( 0 );

url = '/owa/auth/logon.aspx?replaceCurrent=1&url=';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "title>CRYPTOCard Authentication Form - Outlook Web Access" >< buf && "CRYPTOCard Microsoft Exchange Plugin" >< buf )
{
  cpe = 'cpe:/a:safenet-inc:safenet_authentication_service_outlook_web_access_agent';
  set_kb_item( name:"ms/owa/outlook_web_access_agent/installed", value:TRUE);

  register_product( cpe:cpe, location:url, port:port, service:"www" );

  log_message( data:'Detected SafeNet SAS OWA Agent\nCPE: ' + cpe + '\nLocation: ' + url, port:port);
  exit( 0 );
}

exit( 0 );
