# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = 'cpe:/a:magentocommerce:magento';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112663");
  script_version("2021-08-30T14:01:20+0000");
  script_tag(name:"last_modification", value:"2021-08-30 14:01:20 +0000 (Mon, 30 Aug 2021)");
  script_tag(name:"creation_date", value:"2019-11-07 13:37:11 +0000 (Thu, 07 Nov 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_cve_id("CVE-2019-8139", "CVE-2019-8144", "CVE-2019-8148");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # patch version not retrievable

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Magento 2.3.x < 2.3.3 or 2.3.2-p1 Multiple Vulnerabilities - October 19");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_magento_detect.nasl");
  script_mandatory_keys("magento/installed");

  script_tag(name:"summary", value:"Magento is prone to multiple vulnerabilities, including remote code execution (RCE),
  and cross-site scripting (XSS).

  See the referenced advisories for further details on each specific vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Magento 2.3 prior to 2.3.3 or 2.3.2-p1.");

  script_tag(name:"solution", value:"Update to version 2.3.2-p1, 2.3.3 or later.");

  script_xref(name:"URL", value:"https://magento.com/security/patches/magento-2.3.3-and-2.2.10-security-update");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
path = infos['location'];

if(version_in_range(version: version, test_version: "2.3", test_version2: "2.3.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.3.3 or 2.3.2-p1", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
