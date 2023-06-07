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

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814881");
  script_version("2023-03-02T10:19:53+0000");
  script_cve_id("CVE-2019-10901", "CVE-2019-10903", "CVE-2019-10894", "CVE-2019-10895",
                "CVE-2019-10896", "CVE-2019-10899");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-03-02 10:19:53 +0000 (Thu, 02 Mar 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-27 15:28:00 +0000 (Mon, 27 Feb 2023)");
  script_tag(name:"creation_date", value:"2019-04-12 15:52:43 +0530 (Fri, 12 Apr 2019)");
  script_name("Wireshark Security Updates (Apr 2019 - 01) - Mac OS X");

  script_tag(name:"summary", value:"Wireshark is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple
  unspecified errors in GSS-API, DCERPC SPOOLSS, LDSS, DOF, SRVLOC
  dissectors and NetScaler file parser.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to crash Wireshark dissectors by injecting a malformed
  packet onto the wire or by convincing someone to read a malformed packet trace
  file.");

  script_tag(name:"affected", value:"Wireshark versions 2.4.0 to 2.4.13,
  2.6.0 to 2.6.7 and 3.0.0.");

  script_tag(name:"solution", value:"Update to version 2.4.14, 2.6.8, 3.0.1 or later.");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2019-14.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2019-09.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2019-15.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2019-10.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2019-17.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2019-18.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
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

if(version_in_range(version:vers, test_version:"2.4.0", test_version2:"2.4.13")) {
  fix = "2.4.14";
}

else if(version_in_range(version:vers, test_version:"2.6.0", test_version2:"2.6.7")) {
  fix = "2.6.8";
}

else if(version_is_equal(version:vers, test_version:"3.0")) {
  fix = "3.0.1";
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);