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
  script_oid("1.3.6.1.4.1.25623.1.0.148987");
  script_version("2023-10-18T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-10-18 05:05:17 +0000 (Wed, 18 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-12-05 02:58:06 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-05 18:57:00 +0000 (Mon, 05 Dec 2022)");

  script_cve_id("CVE-2022-46159");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse < 2.9.0.beta15 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_discourse_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Any authenticated user can create an unlisted topic. These
  topics, which are not readily available to other users can take up unnecessary site resources.");

  script_tag(name:"affected", value:"Discourse prior to version 2.9.0.beta15.");

  script_tag(name:"solution", value:"Update to version 2.9.0.beta15 or later.");

  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-qf99-xpx6-hgxp");

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

if (version_in_range(version: version, test_version: "2.9.0.beta1", test_version2: "2.9.0.beta14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.9.0.beta15", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
