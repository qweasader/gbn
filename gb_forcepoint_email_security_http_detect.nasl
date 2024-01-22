# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113557");
  script_version("2023-12-19T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-12-19 05:05:25 +0000 (Tue, 19 Dec 2023)");
  script_tag(name:"creation_date", value:"2019-11-08 15:48:22 +0200 (Fri, 08 Nov 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Forcepoint Email Security Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Forcepoint Email Security.");

  script_xref(name:"URL", value:"https://www.forcepoint.com/product/email-security");

  exit(0);
}

CPE = "cpe:/a:forcepoint:email_security:";

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");

port = http_get_port( default: 443 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port: port ) ) ) {
  location = dir;
  if( location == "/" )
    location = "";

  url = location + "/pem/login/pages/login.jsf";

  buf = http_get_cache( port: port, item: url );
  if( buf =~ "^HTTP/1\.[01] 200" && buf =~ "<title>Forcepoint Email Security" ) {

    # nb: For JavaServer Faces active checks (See "login.jsf" above)
    set_kb_item( name: "www/javaserver_faces/detected", value: TRUE );
    set_kb_item( name: "www/javaserver_faces/" + port + "/detected", value: TRUE );

    set_kb_item( name: "forcepoint/email_security/detected", value: TRUE );

    version = "unknown";

    ver = eregmatch( string: buf, pattern: "&nbsp;Version&nbsp;([0-9.]+)" );
    if( ! isnull( ver[1] ) )
      version = ver[1];

    register_and_report_cpe( app: "Forcepoint Email Security",
                             ver: version,
                             concluded: ver[0],
                             base: CPE,
                             expr: "([0-9.]+)",
                             insloc: dir,
                             regPort: port,
                             regService: "www",
                             conclUrl: url );
  }
}

exit( 0 );
