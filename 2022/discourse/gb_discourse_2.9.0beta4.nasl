# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148034");
  script_version("2022-09-19T10:11:35+0000");
  script_tag(name:"last_modification", value:"2022-09-19 10:11:35 +0000 (Mon, 19 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-05-03 07:37:55 +0000 (Tue, 03 May 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-30 18:50:00 +0000 (Wed, 30 Mar 2022)");

  script_cve_id("CVE-2018-25032", "CVE-2022-24804", "CVE-2022-24824", "CVE-2022-24850");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse 2.9.x < 2.9.0.beta4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2018-25032: Discourse ships Nokogiri with the following platform releases which includes
  zlib as a dependency which contains a memory corruption

  - CVE-2022-24804: Names of groups with restricted visibility may be leaked when viewing a
  category

  - CVE-2022-24824: Anonymous user cache poisoning via maliciously formed request

  - CVE-2022-24850: Category group permissions leaked to users that cannot edit a category");

  script_tag(name:"affected", value:"Discourse version 2.9.x prior to 2.9.0.beta4.");

  script_tag(name:"solution", value:"Update to version 2.9.0.beta4 or later.");

  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-8xx7-27hw-w44g");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-v4c9-6m9g-37ff");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-46v9-3jc4-f53w");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-34xr-ff4w-mcpf");

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

if (version_in_range(version: version, test_version: "2.9.0.beta1", test_version2: "2.9.0.beta3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.9.0.beta4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
