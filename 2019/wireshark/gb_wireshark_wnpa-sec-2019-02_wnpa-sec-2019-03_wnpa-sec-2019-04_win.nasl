###############################################################################
# OpenVAS Vulnerability Test
#
# Wireshark Security Updates(wnpa-sec-2019-02_wnpa-sec-2019-03_wnpa-sec-2019-04)-Windows
#
# Authors:
# Vidita V Koushik <vidita@secpod.com>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814392");
  script_version("2021-10-04T14:22:38+0000");
  script_cve_id("CVE-2019-5717", "CVE-2019-5718", "CVE-2019-5719");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-10-04 14:22:38 +0000 (Mon, 04 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-20 01:15:00 +0000 (Fri, 20 Mar 2020)");
  script_tag(name:"creation_date", value:"2019-01-10 15:44:51 +0530 (Thu, 10 Jan 2019)");
  script_name("Wireshark Security Updates (wnpa-sec-2019-02, wnpa-sec-2019-03, wnpa-sec-2019-04) - Windows");

  script_tag(name:"summary", value:"Wireshark is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to input validation
  errors in P_MUL, RTSE, ASN.1, ISAKMP and other dissectors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to crash Wireshark dissectors by injecting a malformed packet into the network
  or by tricking a victim into opening a malicious packet trace file.");

  script_tag(name:"affected", value:"Wireshark versions 2.4.0 to 2.4.11 and
  2.6.0 to 2.6.5.");

  script_tag(name:"solution", value:"Update to version 2.4.12, 2.6.6 or later.");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2019-02.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2019-03.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2019-04.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"2.4.0", test_version2:"2.4.11")) {
  fix = "2.4.12";
}

else if(version_in_range(version:vers, test_version:"2.6.0", test_version2:"2.6.5")) {
  fix = "2.6.6";
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);