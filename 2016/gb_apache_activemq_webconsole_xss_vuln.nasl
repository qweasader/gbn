###############################################################################
# OpenVAS Vulnerability Test
#
# Apache ActiveMQ Web Console Cross-Site Scripting Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:apache:activemq";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808293");
  script_version("2022-04-13T13:17:10+0000");
  script_cve_id("CVE-2016-0782");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-13 13:17:10 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-27 20:29:00 +0000 (Wed, 27 Mar 2019)");
  script_tag(name:"creation_date", value:"2016-08-18 09:00:09 +0530 (Thu, 18 Aug 2016)");

  script_name("Apache ActiveMQ Web Console Cross-Site Scripting Vulnerability");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_activemq_consolidation.nasl");
  script_mandatory_keys("apache/activemq/detected");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/136215");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/84316");
  script_xref(name:"URL", value:"http://activemq.apache.org/security-advisories.data/CVE-2016-0782-announcement.txt");

  script_tag(name:"summary", value:"Apache ActiveMQ is prone to a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an improper user data
  output validation and incorrect permissions configured on Jolokia.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated attackers to conduct cross-site scripting (XSS) attacks and
  consequently obtain sensitive information from a Java memory dump via vectors related to creating a queue.");

  script_tag(name:"affected", value:"Apache ActiveMQ Version 5.x before 5.11.4,
  5.12.x before 5.12.3, and 5.13.x before 5.13.1.");

  script_tag(name:"solution", value:"Update to version 5.11.4 or 5.12.3 or 5.13.1 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! appVer = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if( version_in_range( version:appVer, test_version:"5.0.0", test_version2:"5.11.3" ) ) {
  fix = "5.11.4";
  VULN = TRUE ;
} else if( version_in_range( version:appVer, test_version:"5.12.0", test_version2:"5.12.2" ) ) {
  fix = "5.12.3";
  VULN = TRUE ;
} else if( version_is_equal( version:appVer, test_version:"5.13.0" ) ) {
  fix = "5.13.1";
  VULN = TRUE ;
}

if( VULN ) {
  report = report_fixed_ver( installed_version:appVer, fixed_version:fix );
  security_message( data:report, port:0 );
  exit( 0 );
}

exit( 99 );
