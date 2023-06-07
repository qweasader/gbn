##############################################################################
# OpenVAS Vulnerability Test
#
# EMC Data Protection Advisor Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:dell:emc_data_protection_advisor";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106939");
  script_version("2021-09-16T12:01:45+0000");
  script_tag(name:"last_modification", value:"2021-09-16 12:01:45 +0000 (Thu, 16 Sep 2021)");
  script_tag(name:"creation_date", value:"2017-07-11 15:10:44 +0700 (Tue, 11 Jul 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-17 17:58:00 +0000 (Mon, 17 Jul 2017)");

  script_cve_id("CVE-2017-8002", "CVE-2017-8003");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("EMC Data Protection Advisor Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_emc_data_protection_advisor_detect.nasl");
  script_mandatory_keys("emc_data_protection_advisor/installed");

  script_tag(name:"summary", value:"EMC Data Protection Advisor is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"EMC Data Protection Advisor is prone to multiple vulnerabilities:

  - Multiple Blind SQL Injection Vulnerabilities (CVE-2017-8002)

  - Path Traversal Vulnerability (CVE-2017-8003)");

  script_tag(name:"affected", value:"EMC Data Protection Advisor prior to version 6.4");

  script_tag(name:"solution", value:"Update to 6.4 or later versions.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Jul/12");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "6.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
