# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802766");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2011-2698");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-05-02 16:03:18 +0530 (Wed, 02 May 2012)");
  script_name("Wireshark ANSI A MAP Files Denial of Service Vulnerability (Mac OS X)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_family("Denial of Service");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation allows attackers to crash an affected application,
  denying service to legitimate users.");
  script_tag(name:"affected", value:"Wireshark version 1.6.0
  Wireshark version 1.4.x to 1.4.7 on Mac OS X");
  script_tag(name:"insight", value:"The flaw is caused to an infinite loop was found in the way ANSI A interface
  dissector of the Wireshark network traffic analyzer processed certain ANSI A
  MAP capture files. If Wireshark read a malformed packet off a network or
  opened a malicious packet capture file, it could lead to denial of service.");
  script_tag(name:"solution", value:"Upgrade to Wireshark version 1.4.8 or 1.6.1 or later.");
  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45086");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49071");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2011/07/20/2");
  script_xref(name:"URL", value:"http://anonsvn.wireshark.org/viewvc?view=revision&revision=37930");
  exit(0);
}

include("version_func.inc");

wireVer = get_kb_item("Wireshark/MacOSX/Version");
if(!wireVer){
  exit(0);
}

if(version_is_equal(version:wireVer, test_version:"1.6.0") ||
   version_in_range(version:wireVer, test_version:"1.4.0", test_version2:"1.4.7")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
