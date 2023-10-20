# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802760");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2012-1594");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-04-23 18:08:49 +0530 (Mon, 23 Apr 2012)");
  script_name("Wireshark IEEE 802.11 Dissector Denial of Service Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48548/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52738");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-05.html");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2012/03/28/13");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of
  service.");
  script_tag(name:"affected", value:"Wireshark versions 1.6.x before 1.6.6 on Windows");
  script_tag(name:"insight", value:"The flaw is due to an error in the IEEE 802.11 dissector can be
  exploited to cause an infinite loop via a specially crafted packet.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.6.6 or later.");
  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

sharkVer = get_kb_item("Wireshark/Win/Ver");
if(!sharkVer){
  exit(0);
}

if(version_in_range(version:sharkVer, test_version:"1.6.0", test_version2:"1.6.5")){
  report = report_fixed_ver(installed_version:sharkVer, vulnerable_range:"1.6.0 - 1.6.5");
  security_message(port:0, data:report);
}
