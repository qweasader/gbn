###############################################################################
# OpenVAS Vulnerability Test
#
# Wireshark Denial of Service Vulnerability Sep13 (Mac OS X)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804019");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2013-5717");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-09-27 11:13:03 +0530 (Fri, 27 Sep 2013)");
  script_name("Wireshark Denial of Service Vulnerability Sep13 (Mac OS X)");

  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 1.10.2 or later.");

  script_tag(name:"insight", value:"Flaw is due to an error in the Bluetooth HCI ACL dissector (dissectors/packet-bthci_acl.c).");

  script_tag(name:"affected", value:"Wireshark version 1.10.x before 1.10.2 on Mac OS X.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a DoS (Denial of Service)
  and potentially compromise a vulnerable system.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54765");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62322");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2013-55.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!sharkVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(sharkVer  =~ "^(1\.10)")
{
  if(version_is_less(version:sharkVer, test_version:"1.10.2"))
  {
    report = report_fixed_ver(installed_version:sharkVer, fixed_version:"1.10.2");
    security_message(port: 0, data: report);
    exit(0);
  }
}
