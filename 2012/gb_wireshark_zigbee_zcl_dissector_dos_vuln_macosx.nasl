# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802846");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2010-4301");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-05-04 18:39:35 +0530 (Fri, 04 May 2012)");
  script_name("Wireshark ZigBee ZCL Dissector Denial of Service Vulnerability (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42290");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/3038");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2010-14.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to crash the application.");
  script_tag(name:"affected", value:"Wireshark version 1.4.0 to 1.4.1");
  script_tag(name:"insight", value:"The flaw is due to an error in 'epan/dissectors/packet-zbee-zcl.c' in
  the ZigBee ZCL dissector, which allows remote attackers to cause a denial of
  service (infinite loop) via a crafted ZCL packet.");
  script_tag(name:"solution", value:"Upgrade to Wireshark 1.4.2 or later.");
  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

sharkVer = get_kb_item("Wireshark/MacOSX/Version");
if(!sharkVer){
  exit(0);
}

if(version_in_range(version:sharkVer, test_version:"1.4.0", test_version2:"1.4.1")){
  report = report_fixed_ver(installed_version:sharkVer, vulnerable_range:"1.4.0 - 1.4.1");
  security_message(port:0, data:report);
}
