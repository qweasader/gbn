# SPDX-FileCopyrightText: 2002 David Kyger
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11872");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("ODBC tools check");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 David Kyger");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Remove the specified ODBC tools from the /scripts/tools directory.");

  script_tag(name:"summary", value:"Many Web servers ship with default CGI scripts which allow for ODBC access
  and configuration. Some of these test ODBC tools are present on the remote web server");

  script_tag(name:"impact", value:"ODBC tools could allow a malicious user to hijack and redirect ODBC traffic,
  obtain SQL user names and passwords or write files to the local drive of a vulnerable server.

  Example: /scripts/tools/getdrvrs.exe");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

vuln = FALSE;
report = "The following ODBC tools were found on the server:";

port = http_get_port(default:80);

foreach url( make_list( "/scripts/tools/getdrvrs.exe", "/scripts/tools/dsnform.exe" ) ) {
  if( http_is_cgi_installed_ka( item:url, port:port ) ) {
    report += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
    vuln = TRUE;
  }
}

if( vuln ) {
  security_message( port:port, data:report );
}

exit( 0 );
