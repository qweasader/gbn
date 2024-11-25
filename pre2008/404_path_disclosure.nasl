# SPDX-FileCopyrightText: 2003 Michel Arboi
# SPDX-FileCopyrightText: Improved / extended code / detection routine since 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11714");
  script_version("2024-07-26T05:05:35+0000");
  script_tag(name:"last_modification", value:"2024-07-26 05:05:35 +0000 (Fri, 26 Jul 2024)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  # Note: the way the test is made will lead to detecting some path disclosure issues which might be
  # checked by other plugins (like #11226: Oracle9i jsp error). I have reviewed the reported
  # "path disclosure" errors from bugtraq and the following list includes bugs which will be
  # triggered by the NASL script. Some other "path disclosure" bugs in webservers might not be
  # triggered since they might depend on some specific condition (execution of a cgi, options..)
  # jfs - December 2003
  script_cve_id("CVE-2001-1372", "CVE-2002-0266", "CVE-2002-2008", "CVE-2003-0456");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Non-Existent Page Physical Path Disclosure Vulnerability (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2003 Michel Arboi");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl",
                      "global_settings.nasl", "gb_microsoft_iis_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://web.archive.org/web/20210121154255/http://www.securityfocus.com/bid/3341");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121154255/http://www.securityfocus.com/bid/4035");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121154255/http://www.securityfocus.com/bid/4261");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121154255/http://www.securityfocus.com/bid/5054");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210121154255/http://www.securityfocus.com/bid/8075");

  script_tag(name:"summary", value:"The remote web server is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends multiple crafted HTTP GET requests and checks the
  responses.");

  script_tag(name:"insight", value:"The remote web server reveals the physical path of the webroot
  when asked for a non-existent page.

  Whilst printing errors to the output is useful for debugging applications, this feature should not
  be enabled on production servers.");

  script_tag(name:"affected", value:"The following products are known to be vulnerable:

  - No CVE: Pi3Web version 2.0.0

  - CVE-2001-1372: Oracle 9i Application Server 1.0.2

  - CVE-2002-0266: Thunderstone Texis

  - CVE-2002-2008: Apache Tomcat 4.0.3 for Windows

  - CVE-2003-0456: VisNetic WebSite 3.5

  Other products or versions might be affected as well.");

  script_tag(name:"solution", value:"Update the server or reconfigure it. Please contact the vendor
  of the product for more info.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

exts = make_list( ".", "/", ".html", ".htm", ".jsp", ".shtm", ".shtml", ".cfm" );
asp_exts = make_list( ".asp", ".aspx" );
php_exts = make_list( ".php", ".php3", ".php4", ".php5", ".php7" );

port = http_get_port( default:80 );

# Choose file to request based on what the remote host is supporting
if( http_can_host_asp( port:port ) && http_can_host_php( port:port ) ) {
  exts = make_list( exts, asp_exts, php_exts );
} else if( http_can_host_asp( port:port ) ) {
  exts = make_list( exts, asp_exts );
} else if( http_can_host_php( port:port ) ) {
  exts = make_list( exts, php_exts );
}

report = "The following URL(s) have been determined to disclose a possible sensitive internal path:";

foreach ext( exts ) {

  file = "non-existent-" + rand();
  url = "/" + file + ext;
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, fetch404:TRUE );
  if( ! res ) continue;

  # nb: Windows like path
  # e.g. the following (the /.asp was used / checked like this) which was tested in the original
  # regex included in the first implementation of this check):
  #
  # c:\this\is\a\windows\path\non-existent\.asp
  # c:\anotherone\non-existent\.asp
  # c:\this\is\a\windows\path\non-existent.asp
  # c:\anotherone\non-existent.asp
  #
  # These shouldn't be detected (no path disclosure here):
  #
  # c:\non-existent\.asp
  # c:\non-existent.asp
  #
  # For references, the early implementation of this check had used the following:
  # strcat( "[C-H]:(\\[A-Za-z0-9_.-])*\\", file, "\\", ext )
  #
  windows_pattern = strcat( "[c-hC-H]:\\[A-Za-z0-9_.-\]+\\", file, "(\\)?", ext );
  if( concl = egrep( string:res, pattern:windows_pattern, icase:FALSE ) ) {
    report += '\n\n' + http_report_vuln_url( port:port, url:url );
    report += '\nConcluded from the following response:\n\n' + chomp( concl );
    VULN = TRUE;
  }

  # There might be cases where we're getting redirected with a 30x like e.g.:
  # > HTTP/1.1 301 Moved Permanently
  # > Location: /foo/non-existent.php
  #
  # as there is no path disclosure involved here we're excluding any redirects for the Linux check
  # as this would be a false positive.
  #
  # nb: If we're seeing any additional redirects like e.g. a Javascript or HTML one causing false
  # positives we could exclude them here as well
  #
  if( res =~ "^HTTP/1\.[01] 30." ||
      egrep( string:res, pattern:"^[Ll]ocation\s*:.*" + file + ".*" + ext, icase:FALSE )
    )
    continue;

  # nb: Unix like path
  # e.g. the following (the /.php was used / checked like this) which was tested in the original
  # regex included in the first implementation of this check):
  #
  # /this/is/a/unix/path/non-existent/.php
  # /anotherone/non-existent/.php
  # /this/is/a/unix/path/non-existent.php
  # /anotherone/non-existent.php
  #
  # These shouldn't be detected (no path disclosure here):
  #
  # /non-existent/.php
  # /non-existent.php
  #
  # For references, the early implementation of this check had used the following:
  # strcat( "(/[A-Za-z0-9_.+-])+/", file, "/", ext )
  #
  # nb: As the Linux pattern might be a little bit "weak" we're expecting at least three chars in
  # the path name (via {3,}) for now.
  #
  linux_pattern = strcat( "/[A-Za-z0-9_.+-/]{3,}/", file, "/?", ext );
  if( concl = egrep( string:res, pattern:linux_pattern, icase:FALSE ) ) {
    report += '\n\n' + http_report_vuln_url( port:port, url:url );
    report += '\nConcluded from the following response:\n\n' + chomp( concl );
    VULN = TRUE;
  }
}

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
