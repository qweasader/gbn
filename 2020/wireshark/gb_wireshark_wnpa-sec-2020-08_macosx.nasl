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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817032");
  script_version("2021-10-04T14:22:38+0000");
  script_cve_id("CVE-2020-11647");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-10-04 14:22:38 +0000 (Mon, 04 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-10 20:08:00 +0000 (Wed, 10 Feb 2021)");
  script_tag(name:"creation_date", value:"2020-05-28 12:46:29 +0530 (Thu, 28 May 2020)");
  script_name("Wireshark Security Updates (wnpa-sec-2020-08) - Mac OS X");

  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in handling
  of the 'BACapp' dissector.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to crash the Wireshark.");

  script_tag(name:"affected", value:"Wireshark version 3.2.0 to 3.2.3, 3.0.0 to 3.0.10, 2.6.0 to 2.6.16.");

  script_tag(name:"solution", value:"Update to version 3.2.4, 3.0.11, 2.6.17 or later.");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2020-08");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"3.2.0", test_version2:"3.2.3")) {
  fix = "3.2.4";
}

else if(version_in_range(version:vers, test_version:"3.0.0", test_version2:"3.0.10")) {
  fix = "3.0.11";
}

else if(version_in_range(version:vers, test_version:"2.6.0", test_version2:"2.6.16")) {
  fix = "2.6.17";
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);