###############################################################################
# OpenVAS Vulnerability Test
#
# Wireshark Multiple Denial-of-Service Vulnerabilities-01 June17 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.811070");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2017-9352", "CVE-2017-9351", "CVE-2017-9346", "CVE-2017-9345",
                "CVE-2017-9349", "CVE-2017-9350", "CVE-2017-9344", "CVE-2017-9343",
                "CVE-2017-9354");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-06-02 15:48:52 +0530 (Fri, 02 Jun 2017)");
  script_name("Wireshark Multiple Denial-of-Service Vulnerabilities-01 June17 (Windows)");

  script_tag(name:"summary", value:"Wireshark is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in the epan/dissectors/packet-rgmp.c script within the RGMP
    dissector which could crash.

  - An error in the epan/dissectors/packet-msnip.c script within the MSNIP
    dissector which misuses a NULL pointer.

  - An error in the epan/dissectors/packet-btl2cap.c script within the Bluetooth
    L2CAP dissector which could divide by zero.

  - An error in the epan/dissectors/packet-opensafety.c script within the openSAFETY
    dissector which could crash or exhaust system memory.

  - An error in the epan/dissectors/packet-dcm.c script within the DICOM dissector
    which could go into an infinite loop.

  - An error in the epan/dissectors/packet-slsk.c script within the SoulSeek
    dissector which could go into an infinite loop.

  - An error in the epan/dissectors/packet-dns.c script within the DNS dissector
    which could go into an infinite loop.

  - An error in epan/dissectors/packet-bzr.c script within the Bazaar dissector
    which could go into an infinite loop.

  - An error in epan/dissectors/packet-bootp.c script within the DHCP dissector
    which could read past the end of a buffer.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to crash wireshark or consume excessive CPU resources.");

  script_tag(name:"affected", value:"Wireshark version 2.2.0 through 2.2.6
  and 2.0.0 through 2.0.12 on Windows");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 2.2.7 or
  2.0.13 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-32.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98804");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98808");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98799");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98798");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98803");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98806");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98796");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98797");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98802");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-30.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-29.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-28.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-27.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-25.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-26.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-22.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-24.html");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!wirversion = get_app_version(cpe:CPE)){
  exit(0);
}

if(wirversion =~ "^(2\.2)" && version_is_less(version:wirversion, test_version:"2.2.7")){
  fix = "2.2.7";
}
else if(wirversion =~ "^(2\.0)" && version_is_less(version:wirversion, test_version:"2.0.13")){
  fix = "2.0.13";
}

if(fix)
{
  report = report_fixed_ver(installed_version:wirversion, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
