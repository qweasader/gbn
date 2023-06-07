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
  script_oid("1.3.6.1.4.1.25623.1.0.104476");
  script_version("2022-12-19T10:12:02+0000");
  script_tag(name:"last_modification", value:"2022-12-19 10:12:02 +0000 (Mon, 19 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-19 08:24:26 +0000 (Mon, 19 Dec 2022)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2022-37966", "CVE-2022-37967", "CVE-2022-38023");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Samba Multiple Vulnerabilities (Dec 2022)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_tag(name:"summary", value:"Samba is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - CVE-2022-37966: rc4-hmac Kerberos session keys issued to modern servers

  - CVE-2022-37967: Kerberos constrained delegation ticket forgery possible against Samba AD DC

  - CVE-2022-38023: RC4/HMAC-MD5 NetLogon Secure Channel is weak and should be avoided");

  script_tag(name:"affected", value:"Samba versions prior to 4.15.13, 4.16.x prior to 4.16.8 and
  4.17.x prior to 4.17.4.");

  script_tag(name:"solution", value:"Update to version 4.15.13, 4.16.8, 4.17.4 or later.");

  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2022-37966.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2022-37967.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2022-38023.html");

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

if (version_is_less(version: version, test_version: "4.15.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.15.13 / 4.16.8 / 4.17.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.16.0", test_version_up: "4.16.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.16.8 / 4.17.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.17.0", test_version_up: "4.17.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.17.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
