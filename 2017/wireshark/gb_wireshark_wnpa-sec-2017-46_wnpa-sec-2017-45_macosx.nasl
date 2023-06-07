###############################################################################
# OpenVAS Vulnerability Test
#
# Wireshark Security Updates (wnpa-sec-2017-46_wnpa-sec-2017-45)-MACOSX
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.811945");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2017-15189", "CVE-2017-15190");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-10-12 13:42:39 +0530 (Thu, 12 Oct 2017)");
  script_name("Wireshark Security Updates (wnpa-sec-2017-46_wnpa-sec-2017-45)-MACOSX");

  script_tag(name:"summary", value:"Wireshark is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The DOCSIS dissector could go into an infinite loop.

  - The RTSP dissector could crash.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to make Wireshark consume excessive
  CPU resources by injecting a malformed packet onto the wire or by convincing
  someone to read a malformed packet trace file. It may be possible to make
  Wireshark crash by injecting a malformed packet onto the wire or by convincing
  someone to read a malformed packet trace file.");

  script_tag(name:"affected", value:"Wireshark version 2.4.0 to 2.4.1
  on MACOSX.");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 2.4.2 or
  later.");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-46");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101228");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101229");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-45");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!wirversion = get_app_version(cpe:CPE)){
  exit(0);
}

if(wirversion =~ "^(2\.4)" )
{
  if(version_in_range(version:wirversion, test_version:"2.4.0", test_version2:"2.4.1"))
  {
    report = report_fixed_ver(installed_version:wirversion, fixed_version:"2.4.2");
    security_message(data:report);
    exit(0);
  }
}
exit(0);