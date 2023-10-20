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

CPE = "cpe:/a:flatpress:flatpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118428");
  script_version("2023-10-18T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-10-18 05:05:17 +0000 (Wed, 18 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-12-19 11:00:29 +0000 (Mon, 19 Dec 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-06 05:55:00 +0000 (Fri, 06 Jan 2023)");

  script_cve_id("CVE-2022-4605", "CVE-2022-4606", "CVE-2022-4748", "CVE-2022-4755",
                "CVE-2022-4820", "CVE-2022-4821", "CVE-2022-4822");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("FlatPress < 1.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_flatpress_http_detect.nasl");
  script_mandatory_keys("flatpress/detected");

  script_tag(name:"summary", value:"FlatPress is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-4605: Cross-site Scripting (XSS) - Stored in GitHub repository
  'flatpressblog/flatpress'

  - CVE-2022-4606: PHP Remote File Inclusion in GitHub repository
  'flatpressblog/flatpress'.

  - CVE-2022-4748: Deleting a file might be used to break out of the attaches/images/gallery folder.

  - CVE-2022-4755: Media Manager plugin allows for possible cross-site scripting (XSS) due to
  insufficient input sanitation.

  - CVE-2022-4820: Entry list in Admin Area allows for possible cross-site scripting (XSS) due to
  insufficient input sanitation.

  - CVE-2022-4821: Cross-site scripting (XSS) via uploaded XML and Markdown files with malicious JS.

  - CVE-2022-4822: FlatPress installer allows for possible XSS due to insufficient input
  sanitation.");

  script_tag(name:"affected", value:"FlatPress prior to version 1.3.");

  script_tag(name:"solution", value:"Update to version 1.3 or later.");

  script_xref(name:"URL", value:"https://github.com/flatpressblog/flatpress/commit/742f8b04f233e3cc52bed11f79fcc9911faee776");
  script_xref(name:"URL", value:"https://github.com/flatpressblog/flatpress/commit/c30d52b28483e1e512d0d81758d4c149f02b4068");
  script_xref(name:"URL", value:"https://github.com/flatpressblog/flatpress/issues/179");
  script_xref(name:"URL", value:"https://github.com/flatpressblog/flatpress/issues/177");
  script_xref(name:"URL", value:"https://github.com/flatpressblog/flatpress/issues/180");
  script_xref(name:"URL", value:"https://github.com/flatpressblog/flatpress/issues/178");
  script_xref(name:"URL", value:"https://github.com/flatpressblog/flatpress/issues/176");

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

if (version_is_less(version: version, test_version: "1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
