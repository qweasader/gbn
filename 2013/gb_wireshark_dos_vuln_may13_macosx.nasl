# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803619");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2013-3557", "CVE-2013-3556");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-05-28 13:52:52 +0530 (Tue, 28 May 2013)");
  script_name("Wireshark ASN.1 BER Dissector DoS Vulnerability - May 13 (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/53425");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59997");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60021");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2013-25.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause denial of
  service by injecting a malformed packet.");
  script_tag(name:"affected", value:"Wireshark 1.6.x before 1.6.15 and 1.8.x before 1.8.7 on Mac OS X");
  script_tag(name:"insight", value:"- 'fragment_add_seq_common' function in epan/reassemble.c has an incorrect
    pointer dereference.

  - 'dissect_ber_choice' function in epan/dissectors/packet-ber.c does not
    properly initialize variables.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.6.15 or 1.8.7 or later.");
  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

sharkVer = get_kb_item("Wireshark/MacOSX/Version");
if(sharkVer && sharkVer=~ "^(1.6|1.8)")
{
  if(version_in_range(version:sharkVer, test_version:"1.6.0", test_version2:"1.6.14") ||
     version_in_range(version:sharkVer, test_version:"1.8.0", test_version2:"1.8.6")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
