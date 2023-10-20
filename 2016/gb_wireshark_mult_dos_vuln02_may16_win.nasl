# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807577");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2016-4006", "CVE-2016-4078", "CVE-2016-4079", "CVE-2016-4080",
                "CVE-2016-4081", "CVE-2016-4082");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-03 03:27:00 +0000 (Sat, 03 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-05-03 11:09:01 +0530 (Tue, 03 May 2016)");
  script_name("Wireshark Multiple Denial of Service Vulnerabilities -02 May16 (Windows)");

  script_tag(name:"summary", value:"Wireshark is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - 'epan/proto.c' script does not limit the protocol-tree depth.

  - The IEEE 802.11 dissector does not properly restrict element lists.

  - 'epan/dissectors/packet-pktc.c' script in the PKTC dissector does not
    verify BER identifiers.

  - 'epan/dissectors/packet-pktc.c' script in the PKTC dissector misparses
    timestamp fields.

  - An incorrect integer data type usage by 'epan/dissectors/packet-iax2.c'
    script in the IAX2 dissector.

  - An incorrect array indexing by 'epan/dissectors/packet-gsm_cbch.c' script
    in the GSM CBCH dissector.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct denial of service attack.");

  script_tag(name:"affected", value:"Wireshark version 1.12.x before 1.12.11
  and 2.0.x before 2.0.3 on Windows");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 1.12.11 or
  or 2.0.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2016-26.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2016-24.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2016-23.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2016-22.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2016-21.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2016-25.html");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!wirversion = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:wirversion, test_version:"1.12.0", test_version2:"1.12.10"))
{
  fix = "1.12.11";
  VULN = TRUE ;
}

else if(version_in_range(version:wirversion, test_version:"2.0.0", test_version2:"2.0.2"))
{
  fix = "2.0.3";
  VULN = TRUE ;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:wirversion, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
