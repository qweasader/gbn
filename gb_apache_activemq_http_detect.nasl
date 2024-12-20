# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105330");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-08-24 12:33:07 +0200 (Mon, 24 Aug 2015)");

  script_name("Apache ActiveMQ Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8161);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Apache ActiveMQ.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:8161 );

url = "/admin/index.jsp";

buf = http_get_cache( item:url, port:port );

host = http_host_name( dont_add_port:TRUE );

if( egrep( pattern:"(Apache )?ActiveMQ( Console)?</title>", string:buf, icase:TRUE ) ||
                   'WWW-Authenticate: basic realm="ActiveMQRealm"' >< buf ) {
  version = "unknown";

  set_kb_item( name:"apache/activemq/detected", value:TRUE );
  set_kb_item( name:"apache/activemq/http/detected", value:TRUE );
  set_kb_item( name:"apache/activemq/http/port", value:port );
  set_kb_item( name:"apache/activemq/http/" + port + "/concludedUrl",
               value:http_report_vuln_url( port:port, url:url, url_only:TRUE ) );

  # nb: Basic auth check for default_http_auth_credentials.nasl
  if( 'WWW-Authenticate: basic realm="ActiveMQRealm"' >< buf ) {
    set_kb_item( name:"www/content/auth_required", value:TRUE );
    set_kb_item( name:"www/" + host + "/" + port + "/content/auth_required", value:url );
    set_kb_item( name:"www/" + host + "/" + port + "/ActiveMQ/Web/auth_required", value:url );
    set_kb_item( name:"ActiveMQ/Web/auth_required", value:TRUE );
    set_kb_item( name:"ActiveMQ/Web/auth_or_unprotected", value:TRUE );
  } else if( egrep( pattern:"(Apache )?ActiveMQ( Console)?</title>", string:buf, icase:TRUE ) ) {
    set_kb_item( name:"www/" + host + "/" + port + "/ActiveMQ/Web/unprotected", value:url );
    set_kb_item( name:"ActiveMQ/Web/unprotected", value:TRUE );
    set_kb_item( name:"ActiveMQ/Web/auth_or_unprotected", value:TRUE );
  }

  # nb: Getting version from admin page, in some cases admin page is accessible where we can get the version
  vers = eregmatch( pattern:'Version.*<td><b>([0-9.]+).*<td>ID', string:buf );
  if( ! isnull( vers[1] ) ) {
    version = vers[1];
    set_kb_item( name:"apache/activemq/http/" + port + "/concluded", value:vers[0] );
  }

  set_kb_item( name:"apache/activemq/http/" + port + "/version", value:version );
}

exit( 0 );
