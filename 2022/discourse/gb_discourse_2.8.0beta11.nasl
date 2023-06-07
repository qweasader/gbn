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
  script_oid("1.3.6.1.4.1.25623.1.0.147388");
  script_version("2022-01-26T03:03:43+0000");
  script_tag(name:"last_modification", value:"2022-01-26 03:03:43 +0000 (Wed, 26 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-11 04:20:44 +0000 (Tue, 11 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-24 19:11:00 +0000 (Mon, 24 Jan 2022)");

  script_cve_id("CVE-2022-21642", "CVE-2022-21677", "CVE-2022-21678", "CVE-2022-21684");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse 2.8.x < 2.8.0.beta11 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-21642: Composing a message from topic reveals whisper participants

  - CVE-2022-21677: Group advanced search option may leak group and group's members visibility

  - CVE-2022-21678: Hide user's bio if profile is restricted

  - CVE-2022-21684: Bypass user approval when invited");

  script_tag(name:"affected", value:"Discourse version 2.8.0.beta1 through 2.8.0.beta10.");

  script_tag(name:"solution", value:"Update to version 2.8.0.beta11 or later.");

  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-mx3h-vc7w-r9c6");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-768r-ppv4-5r27");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-jwww-46gv-564m");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-p63q-jp48-h8xh");

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

if (version_in_range(version: version, test_version: "2.8.0.beta1", test_version2: "2.8.0.beta10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.8.0.beta11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
