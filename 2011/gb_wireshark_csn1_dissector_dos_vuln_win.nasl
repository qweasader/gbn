# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802503");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-11-08 11:55:17 +0200 (Tue, 08 Nov 2011)");
  script_cve_id("CVE-2011-4100");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Wireshark CSN.1 Dissector Denial of Service Vulnerability (Windows)");

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause a denial of service via
  via a malformed packet.");
  script_tag(name:"affected", value:"Wireshark version 1.6.x before 1.6.3");
  script_tag(name:"insight", value:"The flaw is due to an error in csnStreamDissector function in
  epan/dissectors/packet-csn1.c in the CSN.1 dissector, which fails to
  initialize a certain variable.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.6.3 or later.");
  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=750643");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50479");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2011/11/01/9");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2011-17.html");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6351");
  script_xref(name:"URL", value:"http://anonsvn.wireshark.org/viewvc?view=revision&revision=39140");
  exit(0);
}

include("version_func.inc");

wiresharkVer = get_kb_item("Wireshark/Win/Ver");
if(!wiresharkVer){
  exit(0);
}

if(version_in_range(version:wiresharkVer, test_version:"1.6.0", test_version2:"1.6.2")){
  report = report_fixed_ver(installed_version:wiresharkVer, vulnerable_range:"1.6.0 - 1.6.2");
  security_message(port: 0, data: report);
}
