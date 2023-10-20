# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801036");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-11-04 07:03:36 +0100 (Wed, 04 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3829");
  script_name("Wireshark 'wiretap/erf.c' Unsigned Integer Wrap Vulnerability - Nov09 (Windows)");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/676492");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36846");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3849");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  script_tag(name:"impact", value:"Successful remote exploitation will let the attacker execute arbitrary code
  or cause a Denial of Service.");
  script_tag(name:"affected", value:"Wireshark version prior to 1.2.2 on Windows.");
  script_tag(name:"insight", value:"The flaw exists due to an integer overflow error in 'wiretap/erf.c' when
  processing an 'erf' file causes Wireshark to allocate a very large buffer.");
  script_tag(name:"solution", value:"Upgrade to Wireshark 1.2.2.");
  script_tag(name:"summary", value:"Wireshark is prone to unsigned integer wrap vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

sharkVer = get_kb_item("Wireshark/Win/Ver");
if(!sharkVer)
  exit(0);

if(version_is_less(version:sharkVer, test_version:"1.2.2")){
  report = report_fixed_ver(installed_version:sharkVer, fixed_version:"1.2.2");
  security_message(port: 0, data: report);
}
