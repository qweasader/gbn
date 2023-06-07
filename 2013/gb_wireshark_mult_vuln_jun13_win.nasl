###############################################################################
# OpenVAS Vulnerability Test
#
# Wireshark Multiple Vulnerabilities - June 13 (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803654");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2013-4082", "CVE-2013-4080", "CVE-2013-4079", "CVE-2013-4078",
                "CVE-2013-4077", "CVE-2013-4076", "CVE-2013-4075");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-05-28 13:30:52 +0530 (Tue, 28 May 2013)");
  script_name("Wireshark Multiple Vulnerabilities - June 13 (Windows)");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1028648");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60495");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60498");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60499");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60501");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60502");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60503");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60506");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.8.8.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.6.16.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause application
  crash, consume memory or heap-based buffer overflow.");

  script_tag(name:"affected", value:"Wireshark 1.8.x before 1.8.8 on Windows.");

  script_tag(name:"insight", value:"Multiple flaws due to errors in,

  - 'epan/dissectors/packet-gmr1_bcch.c' in GMR-1 BCCH dissector

  - dissect_iphc_crtp_fh() function in 'epan/dissectors/packet-ppp.c' in PPP
  dissector

  - Array index error in NBAP dissector

  - 'epan/dissectors/packet-rdp.c' in the RDP dissector

  - dissect_schedule_message() function in 'epan/dissectors/packet-gsm_cbch.c'
  in GSM CBCH dissector

  - dissect_r3_upstreamcommand_queryconfig() function in
  'epan/dissectors/packet-assa_r3.c' in Assa Abloy R3 dissector

  - vwr_read() function in 'wiretap/vwr.c' in Ixia IxVeriWave file parser.");

  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.8.8 or later.");

  script_tag(name:"summary", value:"Wireshark is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

sharkVer = get_kb_item("Wireshark/Win/Ver");

if(sharkVer && sharkVer=~ "^1\.8")
{
  if(version_in_range(version:sharkVer, test_version:"1.8.0", test_version2:"1.8.7"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
