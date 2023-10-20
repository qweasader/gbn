# SPDX-FileCopyrightText: 2006 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.20376");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2005-4586");
  script_xref(name:"OSVDB", value:"22039");
  script_name("PHPSurveyor sid SQL Injection Flaw");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2006 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to PHPSurveyor version 0.991 or later.");

  script_tag(name:"summary", value:"The remote version of PHPSurveyor is prone to a SQL injection flaw.");

  script_tag(name:"impact", value:"Using specially crafted requests, an attacker can manipulate database
  queries on the remote system.");

  script_xref(name:"URL", value:"http://www.phpsurveyor.org/mantis/view.php?id=286");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/16077");
  script_xref(name:"URL", value:"http://sourceforge.net/project/shownotes.php?release_id=381050&group_id=74605");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if (!http_can_host_php(port:port) )
  exit(0);

foreach dir( make_list_unique( "/phpsurveyor", "/survey", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string(dir,"/admin/admin.php?sid=0'");

  if(http_vuln_check(port:port, url:url,pattern:"mysql_num_rows(): supplied argument is not a valid MySQL .+/admin/html.php")) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
