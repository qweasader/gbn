###############################################################################
# OpenVAS Vulnerability Test
#
# SolarWinds Orion NPM Multiple Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:solarwinds:orion_network_performance_monitor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812219");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2017-9538", "CVE-2017-9537", "CVE-2017-9539");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-09 20:01:00 +0000 (Tue, 09 Oct 2018)");
  script_tag(name:"creation_date", value:"2017-11-21 11:43:13 +0530 (Tue, 21 Nov 2017)");

  script_name("SolarWinds Orion NPM Multiple Vulnerabilities");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_solarwinds_orion_npm_consolidation.nasl");
  script_mandatory_keys("solarwinds/orion/npm/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/541263/100/0/threaded");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101066");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101071");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/541262/100/0/threaded");
  script_xref(name:"URL", value:"https://support.solarwinds.com/Success_Center/Orion_Platform/Orion_Documentation/Orion_Platform_2017.3_Hotfix_1");

  script_tag(name:"summary", value:"SolarWinds Orion NPM is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An incorrect implementation of a directory-traversal protection mechanism.

  - An improper validation of user supplied input in the 'Add Node' function.

  - An unspecified error.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to execute arbitrary script code in the browser of an
  unsuspecting user in the context of the affected site. This may allow the
  attacker to steal cookie-based authentication credentials and launch other
  attacks and cause denial-of-service conditions, denying service to legitimate
  users.");

  script_tag(name:"affected", value:"SolarWinds Orion NPM version 12.0.15300.90.");

  script_tag(name:"solution", value:"Apply the hotfix SolarWinds Orion Platform
  2017.3 Hotfix 1.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
location = infos['location'];

if (version_is_equal(version: version, test_version: "12.0.15300.90")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Apply SolarWinds Orion Platform 2017.3 Hotfix 1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);