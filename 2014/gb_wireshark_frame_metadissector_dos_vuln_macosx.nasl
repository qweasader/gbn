# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804667");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2014-4020");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-07-07 10:17:26 +0530 (Mon, 07 Jul 2014)");
  script_name("Wireshark 'Frame Metadissector' Denial of Service Vulnerability (Mac OS X)");

  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to an error in 'dissect_frame' function in
  epan/dissectors/packet-frame.c within the frame metadissector.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct a DoS
  (Denial of Service) attack.");

  script_tag(name:"affected", value:"Wireshark version 1.10.0 through 1.10.7 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 1.10.8 or later.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/58832");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/68044");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2014-07.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!sharkVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(sharkVer  =~ "^(1\.10)")
{
  if(version_in_range(version:sharkVer, test_version:"1.10.0", test_version2:"1.10.7"))
  {
    report = report_fixed_ver(installed_version:sharkVer, vulnerable_range:"1.10.0 - 1.10.7");
    security_message(port:0, data:report);
    exit(0);
  }
}
