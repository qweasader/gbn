###############################################################################
# OpenVAS Vulnerability Test
#
# Apache ActiveMQ Arbitrary Code Execution Vulnerability June16
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.808146");
  script_version("2022-08-09T10:11:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-3088");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-27 20:29:00 +0000 (Wed, 27 Mar 2019)");
  script_tag(name:"creation_date", value:"2016-06-06 16:11:05 +0530 (Mon, 06 Jun 2016)");

  script_name("Apache ActiveMQ Arbitrary Code Execution Vulnerability June16");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_activemq_consolidation.nasl");
  script_mandatory_keys("apache/activemq/detected");

  script_xref(name:"URL", value:"http://activemq.apache.org/security-advisories.data/CVE-2016-3088-announcement.txt");

  script_tag(name:"summary", value:"Apache ActiveMQ is prone to an arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in 'fileserver' web application, which does
  not validate 'HTTP PUT' and 'HTTP MOVE' requests properly.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to replace web application files with malicious code and perform remote code execution on the system.");

  script_tag(name:"affected", value:"Apache ActiveMQ Version 5.x to 5.13.2.");

  script_tag(name:"solution", value:"Upgrade to Apache ActiveMQ Version 5.14.0 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! appVer = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if( version_in_range( version:appVer, test_version:"5.0.0", test_version2:"5.13.2" ) ) {
  report = report_fixed_ver( installed_version:appVer, fixed_version:"5.14.0" );
  security_message( data:report, port:0 );
  exit( 0 );
}

exit( 99 );