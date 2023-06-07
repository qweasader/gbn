# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:prestashop:prestashop";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142486");
  script_version("2022-07-20T10:33:02+0000");
  script_tag(name:"last_modification", value:"2022-07-20 10:33:02 +0000 (Wed, 20 Jul 2022)");
  script_tag(name:"creation_date", value:"2019-06-04 07:36:57 +0000 (Tue, 04 Jun 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-28 14:59:00 +0000 (Tue, 28 May 2019)");

  script_cve_id("CVE-2019-11876");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PrestaShop <= 1.7.5.2 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_prestashop_http_detect.nasl");
  script_mandatory_keys("prestashop/detected");

  script_tag(name:"summary", value:"PrestaShop is prone to a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The shop_country parameter in the install/index.php installation
  script/component is affected by Reflected XSS. Exploitation by a malicious actor requires the user to follow the
  initial stages of the setup (accepting terms and conditions) before executing the malicious link.");

  script_tag(name:"affected", value:"PrestaShop version 1.7.5.2 and probably prior.");

  script_tag(name:"solution", value:"Update to version 1.7.6 or later.");

  script_xref(name:"URL", value:"https://www.logicallysecure.com/blog/xss-presta-xss-drupal/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

# version_regex is used like this because the HTTP detection might only extract the major.minor
# version like 1.7 and the version check below would cause a false positive in that case.
if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^(0\.|1\.[0-6]|1\.7\.[0-9]+)"))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less_equal(version: version, test_version: "1.7.5.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.7.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
