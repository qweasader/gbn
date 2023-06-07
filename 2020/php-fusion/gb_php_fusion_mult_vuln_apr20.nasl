# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:php-fusion:php-fusion";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143874");
  script_version("2021-07-22T11:01:40+0000");
  script_tag(name:"last_modification", value:"2021-07-22 11:01:40 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"creation_date", value:"2020-05-11 07:04:44 +0000 (Mon, 11 May 2020)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-01 17:17:00 +0000 (Tue, 01 Jun 2021)");

  script_cve_id("CVE-2020-12438", "CVE-2020-12461", "CVE-2020-12706", "CVE-2020-12708", "CVE-2020-12718",
                "CVE-2020-14960", "CVE-2020-15041", "CVE-2020-24949");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP-Fusion < 9.03.60 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_php_fusion_detect.nasl");
  script_mandatory_keys("php-fusion/detected");

  script_tag(name:"summary", value:"PHP-Fusion is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"PHP-Fusion is prone to multiple vulnerabilities:

  - Multiple cross-site scripting vulnerabilities (CVE-2020-12438, CVE-2020-12706, CVE-2020-12708, CVE-2020-12718,
    CVE-2020-15041)

  - Multiple SQL injection vulnerabilities (CVE-2020-12461, CVE-2020-14960)

  - Remote code execution vulnerability in downloads/downloads.php (CVE-2020-24949)");

  script_tag(name:"affected", value:"PHP-Fusion version 9.03.50 and probably prior.");

  script_tag(name:"solution", value:"Update to version 9.03.60 or later.");

  script_xref(name:"URL", value:"https://github.com/php-fusion/PHP-Fusion/issues/2307");
  script_xref(name:"URL", value:"https://github.com/php-fusion/PHP-Fusion/issues/2308");
  script_xref(name:"URL", value:"https://github.com/php-fusion/PHP-Fusion/issues/2306");
  script_xref(name:"URL", value:"https://github.com/php-fusion/PHP-Fusion/issues/2310");
  script_xref(name:"URL", value:"https://github.com/php-fusion/PHP-Fusion/issues/2309");
  script_xref(name:"URL", value:"https://github.com/php-fusion/PHP-Fusion/issues/2327");
  script_xref(name:"URL", value:"https://github.com/php-fusion/PHP-Fusion/issues/2330");
  script_xref(name:"URL", value:"https://github.com/php-fusion/PHP-Fusion/issues/2312");
  script_xref(name:"URL", value:"https://www.php-fusion.co.uk/infusions/news/news.php?readmore=645");

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

if (version_is_less_equal(version: version, test_version: "9.03.50")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.03.60", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
