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

CPE = "cpe:/a:magentocommerce:magento";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144821");
  script_version("2021-07-08T11:00:45+0000");
  script_tag(name:"last_modification", value:"2021-07-08 11:00:45 +0000 (Thu, 08 Jul 2021)");
  script_tag(name:"creation_date", value:"2020-10-23 09:40:40 +0000 (Fri, 23 Oct 2020)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-12 17:58:00 +0000 (Thu, 12 Nov 2020)");

  script_cve_id("CVE-2020-24407", "CVE-2020-24400", "CVE-2020-24402", "CVE-2020-24401", "CVE-2020-24404",
                "CVE-2020-24406", "CVE-2020-24408", "CVE-2020-24405", "CVE-2020-24403");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Magento < 2.3.6, 2.4.x < 2.4.1 Multiple Vulnerabilities (APSB20-59)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_magento_detect.nasl");
  script_mandatory_keys("magento/installed");

  script_tag(name:"summary", value:"Magento is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation could lead to arbitrary code execution.");

  script_tag(name:"affected", value:"Magento version 2.3.5-p2 and prior and 2.4.0.");

  script_tag(name:"solution", value:"Update to version 2.3.6, 2.4.1 or later.");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/magento/apsb20-59.html");

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

if (version_is_less(version: version, test_version: "2.3.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.3.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version == "2.4.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.4.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
