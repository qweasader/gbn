###############################################################################
# OpenVAS Vulnerability Test
#
# IBM WebSphere MQ 9.0.1 And 9.0.2 Information Disclosure
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113067");
  script_version("2022-04-13T11:57:07+0000");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2017-12-08 14:38:39 +0100 (Fri, 08 Dec 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-1337");

  script_name("IBM WebSphere MQ 9.0.1 And 9.0.2 Information Disclosure");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ibm_websphere_mq_consolidation.nasl");
  script_mandatory_keys("ibm_websphere_mq/detected");

  script_tag(name:"summary", value:"IBM WebSphere MQ 9.0.1 and 9.0.2 Java/JMS application can incorrectly transmit
user credentials in plain text.");

  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"IBM WebSphere MQ 8.0.0.0 through 8.0.0.6, 9.0.0.0 through 9.0.0.1 and 9.0.1
through 9.0.2");

  script_tag(name:"solution", value:"Update IBM WebSphere MQ to 8.0.0.7 or 9.0.0.2 or 9.0.3 respectively.");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22003853");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99493");
  script_xref(name:"URL", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/126245");

  exit(0);
}

CPE = "cpe:/a:ibm:websphere_mq";

include( "host_details.inc" );
include( "version_func.inc" );

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe:CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
path = infos['location'];

if( version_in_range( version: version, test_version: "8.0.0.0", test_version2: "8.0.0.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.0.0.7", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "9.0.0.0", test_version2: "9.0.0.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.0.0.2", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "9.0.1", test_version2: "9.0.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "9.0.3", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
