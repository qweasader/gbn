# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100598");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-04-23 13:12:25 +0200 (Fri, 23 Apr 2010)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-1157");
  script_name("Apache Tomcat Authentication Header Realm Name Information Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_apache_tomcat_consolidation.nasl");
  script_mandatory_keys("apache/tomcat/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39635");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-5.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-6.html");

  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=revision&revision=936540");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=revision&revision=936541");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/510879");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a remote information-disclosure
  vulnerability.");

  script_tag(name:"impact", value:"Remote attackers can exploit this issue to obtain the host name or IP
  address of the Tomcat server. Information harvested may lead to further attacks.");

  script_tag(name:"affected", value:"Tomcat 5.5.0 through 5.5.29 Tomcat 6.0.0 through 6.0.26

  Tomcat 3.x, 4.0.x, and 5.0.x may also be affected.");

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
    version_in_range( version:vers, test_version:"6.0.0", test_version2:"6.0.26" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.5.30/6.0.27", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
