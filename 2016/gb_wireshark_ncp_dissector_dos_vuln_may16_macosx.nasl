###############################################################################
# OpenVAS Vulnerability Test
#
# Wireshark NCP dissector Denial of Service Vulnerability May16 (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807580");
  script_version("2021-10-07T09:32:32+0000");
  script_cve_id("CVE-2016-4085");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-10-07 09:32:32 +0000 (Thu, 07 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-03 03:27:00 +0000 (Sat, 03 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-05-03 11:52:58 +0530 (Tue, 03 May 2016)");
  script_name("Wireshark NCP dissector DoS Vulnerability (May 2016) - Mac OS X");

  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to stack-based buffer overflow in the
  'epan/dissectors/packet-ncp2222.inc' script in the 'NCP dissector'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct
  a DoS attack or possibly have unspecified other impact.");

  script_tag(name:"affected", value:"Wireshark version 1.12.x before 1.12.11.");

  script_tag(name:"solution", value:"Update to version 1.12.11 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2016-28.html");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_in_range(version:vers, test_version:"1.12.0", test_version2:"1.12.10")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.12.11");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);