# SPDX-FileCopyrightText: 2004 David Kyger
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12085");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Apache Tomcat servlet/JSP container default files");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Kyger");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("apache/tomcat/http/detected");

  script_tag(name:"summary", value:"The Apache Tomcat servlet/JSP container has default files installed.");

  script_tag(name:"insight", value:"Default files, such as documentation, default Servlets and JSPs were found on
  the Apache Tomcat servlet/JSP container.");

  script_tag(name:"impact", value:"These files should be removed as they may help an attacker to guess the
  exact version of the Apache Tomcat which is running on this host and may
  provide other useful information.");

  script_tag(name:"solution", value:"Remove default files, example JSPs and Servlets from the Tomcat
  Servlet/JSP container.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

report = 'The following default files were found : \n';
found = "";
pat1 = "The Jakarta Project";
pat2 = "Documentation Index";
pat3 = "Examples with Code";
pat4 = "Servlet API";
pat5 = "Snoop Servlet";
pat6 = "Servlet Name";
pat7 = "JSP Request Method";
pat8 = "Servlet path";
pat9 = "session scoped beans";
pat9 = "Java Server Pages";
pat10 = "session scoped beans";

if( ! port = get_app_port( cpe:CPE, service:"www" ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

foreach url( make_list( "/tomcat-docs/index.html",
                        "/examples/servlets/index.html",
                        "/examples/servlet/SnoopServlet",
                        "/examples/jsp/snp/snoop.jsp",
                        "/examples/jsp/index.html" ) ) {

  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req );

  if( isnull( buf ) ) continue;

  if( ( pat1 >< buf && pat2 >< buf ) || ( pat3 >< buf && pat4 >< buf ) || ( pat5 >< buf && pat6 >< buf ) ||
      ( pat7 >< buf && pat8 >< buf ) || ( pat9 >< buf && pat10 >< buf ) ) {
    found += http_report_vuln_url( port:port, url:url, url_only:TRUE ) + '\n';
    vuln = TRUE;
  }
}

if( vuln ) {
  security_message( port:port, data:report + found );
  exit( 0 );
}

exit( 99 );
