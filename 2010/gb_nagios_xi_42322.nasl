###############################################################################
# OpenVAS Vulnerability Test
#
# Nagios XI Multiple Cross Site Request Forgery Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:nagios:nagiosxi";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100753");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-08-10 14:55:08 +0200 (Tue, 10 Aug 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Nagios XI Multiple Cross Site Request Forgery Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42322");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/512967");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_nagios_XI_detect.nasl");
  script_mandatory_keys("nagiosxi/installed");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Reportedly, these issues have been fixed in Nagios XI 2009R1.2C.
  Please see the references for more information.");

  script_tag(name:"summary", value:"Nagios XI is prone to multiple cross-site request-forgery
  vulnerabilities because the application fails to properly validate HTTP requests.");

  script_tag(name:"insight", value:"Successful exploit requires that the 'nagiosadmin' be logged into the
  web interface.");

  script_tag(name:"impact", value:"Attackers can exploit these issues to gain unauthorized access to the
  affected application and perform certain administrative actions.");

  script_tag(name:"affected", value:"Nagios XI 2009R1.2B is vulnerable, other versions may also be affected.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_less_equal(version: version, test_version: "2009R1.2B")) {
  report = report_fixed_ver(installed_version:version, vulnerable_range:"Less or equal to 2009R1.2B", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
