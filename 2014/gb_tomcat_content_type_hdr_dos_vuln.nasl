# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804251");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2014-0050");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-03-24 15:09:34 +0530 (Mon, 24 Mar 2014)");
  script_name("Apache Tomcat Content-Type Header Denial Of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_apache_tomcat_consolidation.nasl");
  script_mandatory_keys("apache/tomcat/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56830");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65400");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/90987");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/31615");
  script_xref(name:"URL", value:"http://blog.spiderlabs.com/2014/02/cve-2014-0050-exploit-with-boundaries-loops-without-boundaries.html");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper handling of Content-Type HTTP header for
  multipart requests");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause denial of
  service condition.");

  script_tag(name:"affected", value:"Apache Tomcat version 7.0.x before 7.0.51 and 8.0.0 before 8.0.2");

  script_tag(name:"solution", value:"Upgrade to 7.0.51, 8.0.2 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_in_range( version:vers, test_version:"7.0.0", test_version2:"7.0.50" ) ||
    version_in_range( version:vers, test_version:"8.0.0.RC1", test_version2:"8.0.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"7.0.51/8.0.2", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );