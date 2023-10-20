# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801434");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-08-19 10:23:11 +0200 (Thu, 19 Aug 2010)");
  script_cve_id("CVE-2010-2994");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Wireshark Stack-based Buffer Overflow Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2010-08.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.2.10.html");

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause buffer overflow.");
  script_tag(name:"affected", value:"Wireshark version 1.2.0 through 1.2.9
  Wireshark version 0.10.13 through 1.0.14");
  script_tag(name:"insight", value:"The flaw is due to an error in handling 'ASN.1 BER dissector' which
  could be used to exhaust stack memory.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.0.15 or 1.2.10 or later.");
  script_tag(name:"summary", value:"Wireshark is prone to Stack-based Buffer Overflow Vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

wiresharkVer = get_kb_item("Wireshark/Win/Ver");
if(!wiresharkVer){
  exit(0);
}

if(version_in_range(version:wiresharkVer, test_version:"1.2.0", test_version2:"1.2.9")||
   version_in_range(version:wiresharkVer, test_version:"0.10.13", test_version2:"1.0.14")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
