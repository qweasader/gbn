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

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143243");
  script_version("2021-09-06T11:01:35+0000");
  script_tag(name:"last_modification", value:"2021-09-06 11:01:35 +0000 (Mon, 06 Sep 2021)");
  script_tag(name:"creation_date", value:"2019-12-12 03:23:10 +0000 (Thu, 12 Dec 2019)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-29 13:15:00 +0000 (Sat, 29 May 2021)");

  script_cve_id("CVE-2019-14861", "CVE-2019-14870");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Samba Multiple Vulnerabilities (CVE-2019-14861, CVE-2019-14870)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_tag(name:"summary", value:"Samba is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Samba is prone to multiple vulnerabilities:

  - Samba AD DC zone-named record Denial of Service in DNS management server (CVE-2019-14861)

  - DelegationNotAllowed not being enforced in protocol transition on Samba AD DC (CVE-2019-14870)");

  script_tag(name:"affected", value:"Samba versions 4.x.");

  script_tag(name:"solution", value:"Update to version 4.9.17, 4.10.11, 4.11.3 or later.");

  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2019-14861.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2019-14870.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "4.0.0", test_version2: "4.9.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.9.17", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.10.0", test_version2: "4.10.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.10.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "4.11.0", test_version2: "4.11.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.11.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
