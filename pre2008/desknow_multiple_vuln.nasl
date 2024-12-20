# SPDX-FileCopyrightText: 2005 Noam Rathaus
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16308");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2005-0332");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12421");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("DeskNow Mail and Collaboration Server Directory Traversal Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade to DeskNow version 2.5.14 or newer.");

  script_tag(name:"summary", value:"A directory traversal vulnerability was found in DeskNow webmail
  file attachment upload feature that may be exploited to upload files to arbitrary locations on the
  server.

  A second directory traversal vulnerability exists in the document repository file delete feature.");

  script_tag(name:"impact", value:"A malicious webmail user may upload a JSP file to the script directory
  of the server, and executing it by requesting the URL of the upload JSP file.

  The second vulnerability may be exploited to delete arbitrary files on the server.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:8080 );

foreach dir( make_list_unique( "/desknow", http_cgi_dirs( port:port ) ) ) {

  if(dir == "/")
    dir = "";

  r = http_get_cache(item:string(dir, "/index.html"), port:port);
  if(!r)
    continue;

  if ( egrep(pattern:"DeskNow&reg; (0\.|1\.|2\.[0-4]\.|2\.5\.[0-9][^0-9]|2\.5\.1[0-3])", string:r) ) {
    security_message(port:port);
    exit(0);
  }
}

exit( 99 );
