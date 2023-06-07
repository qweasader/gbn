# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802900");
  script_version("2023-03-24T10:19:42+0000");
  script_cve_id("CVE-2011-1138");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-03-24 10:19:42 +0000 (Fri, 24 Mar 2023)");
  script_tag(name:"creation_date", value:"2012-06-27 15:29:48 +0530 (Wed, 27 Jun 2012)");
  script_name("Wireshark DoS Vulnerability March-11 (Mac OS X)");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2011-04.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46636");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5722");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.4.4.html");

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause a denial of
  service.");
  script_tag(name:"affected", value:"Wireshark version 1.4.0 through 1.4.3 on Mac Os X");
  script_tag(name:"insight", value:"The flaw is due to 'Off-by-one' error in the dissect_6lowpan_iphc
  function in packet-6lowpan.c");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.4.4 or later.");
  script_tag(name:"summary", value:"Wireshark is prone to multiple denial of service (DoS) vulnerabilities.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

wiresharkVer = get_kb_item("Wireshark/MacOSX/Version");
if(!wiresharkVer){
  exit(0);
}

if(version_in_range(version:wiresharkVer, test_version:"1.4.0", test_version2:"1.4.3")){
  report = report_fixed_ver(installed_version:wiresharkVer, vulnerable_range:"1.4.0 - 1.4.3");
  security_message(port:0, data:report);
}
