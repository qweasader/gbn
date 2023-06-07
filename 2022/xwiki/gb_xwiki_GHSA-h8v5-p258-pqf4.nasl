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

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148081");
  script_version("2022-05-19T12:23:28+0000");
  script_tag(name:"last_modification", value:"2022-05-19 12:23:28 +0000 (Thu, 19 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-10 02:01:44 +0000 (Tue, 10 May 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-17 14:18:00 +0000 (Tue, 17 May 2022)");

  script_cve_id("CVE-2022-29161");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki Crypto API Vulnerability (GHSA-h8v5-p258-pqf4)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"XWiki is prone to a vulnerability in the Crypto API.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"XWiki Crypto API will generate X509 certificates signed by
  default using SHA1 with RSA, which is not considered safe anymore for use in certificate
  signatures, due to the risk of collisions with SHA1.

  Note that this API is never used in XWiki Standard but it might be used in some extensions of
  XWiki.");

  script_tag(name:"affected", value:"XWiki versions prior to 13.10.6 and 14.x prior to 14.3.1.");

  script_tag(name:"solution", value:"Update to version 13.10.6, 14.3.1, 14.4-rc-1 or later.");

  script_xref(name:"URL", value:"https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-h8v5-p258-pqf4");

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

if (version_is_less(version: version, test_version: "13.10.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "13.10.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "14.0", test_version_up: "14.3.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.3.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
