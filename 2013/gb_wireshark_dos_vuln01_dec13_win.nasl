###############################################################################
# OpenVAS Vulnerability Test
#
# Wireshark 'SIP' and 'NTLMSSP' Denial of Service Vulnerability-01 Dec13 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.804049");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2013-7112", "CVE-2013-7114");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-12-30 20:26:43 +0530 (Mon, 30 Dec 2013)");
  script_name("Wireshark 'SIP' and 'NTLMSSP' Denial of Service Vulnerability-01 Dec13 (Windows)");

  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 1.8.12 or 1.10.4 or later.");

  script_tag(name:"insight", value:"Flaw is due to an error within the SIP dissector (epan/dissectors/packet-sip.c)
  and NTLMSSP v2 dissector.");

  script_tag(name:"affected", value:"Wireshark version 1.8.x before 1.8.12 and 1.10.x before 1.10.4 on Windows.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a DoS (Denial of Service)
  and potentially compromise a vulnerable system.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56097");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64411");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64412");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2013-66.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!sharkVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(sharkVer  =~ "^(1\.(8|10))")
{
  if(version_in_range(version:sharkVer, test_version:"1.8.0", test_version2:"1.8.11")||
     version_in_range(version:sharkVer, test_version:"1.10.0", test_version2:"1.10.3"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
