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

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104259");
  script_version("2023-10-19T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"creation_date", value:"2022-07-28 07:34:46 +0000 (Thu, 28 Jul 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-31 15:16:00 +0000 (Wed, 31 Aug 2022)");

  script_cve_id("CVE-2022-2031", "CVE-2022-32742", "CVE-2022-32746");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Samba Multiple Vulnerabilities (Jul 2022)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_tag(name:"summary", value:"Samba is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2022-2031: Samba AD users can bypass certain restrictions associated with changing passwords

  - CVE-2022-32742: Server memory information leak via SMB1

  - CVE-2022-32746: Samba AD users can induce a use-after-free in the server process with an LDAP
  add or modify request");

  script_tag(name:"affected", value:"Samba versions prior to 4.14.14, 4.15.x prior to 4.15.9 and
  4.16.x prior to 4.16.4.");

  script_tag(name:"solution", value:"Update to version 4.14.14, 4.15.9, 4.16.4 or later.");

  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2022-2031.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2022-32742.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2022-32746.html");

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

if (version_is_less(version: version, test_version: "4.14.14")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.14.14 / 4.15.9 / 4.16.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.15.0", test_version_up: "4.15.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.15.9 / 4.16.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.16.0", test_version_up: "4.16.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.16.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
