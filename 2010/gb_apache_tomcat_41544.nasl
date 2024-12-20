# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100712");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-07-13 12:45:31 +0200 (Tue, 13 Jul 2010)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_cve_id("CVE-2010-2227");
  script_name("Apache Tomcat 'Transfer-Encoding' Information Disclosure and Denial Of Service Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_apache_tomcat_consolidation.nasl");
  script_mandatory_keys("apache/tomcat/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41544");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-5.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-6.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-7.html");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/512272");

  script_tag(name:"solution", value:"The vendor released updates. Please see the references for more
  information.");

  script_tag(name:"summary", value:"Apache Tomcat is prone to multiple remote vulnerabilities including
  information-disclosure and denial-of-service issues.");

  script_tag(name:"impact", value:"Remote attackers can exploit these issues to cause denial-of-service
  conditions or gain access to potentially sensitive information,
  information obtained may lead to further attacks.");

  script_tag(name:"affected", value:"Tomcat 5.5.0 to 5.5.29 Tomcat 6.0.0 to 6.0.27 Tomcat 7.0.0

  Tomcat 3.x, 4.x, and 5.0.x may also be affected.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

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

if( version_in_range( version:vers, test_version:"5.5.0", test_version2:"5.5.29" ) ||
    version_in_range( version:vers, test_version:"6.0.0", test_version2:"6.0.27" ) ||
    version_is_equal( version:vers, test_version:"7.0.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.5.30/6.0.28/7.0.1", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
