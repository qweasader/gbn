# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810527");
  script_version("2024-07-22T05:05:40+0000");
  script_cve_id("CVE-2017-5596", "CVE-2017-5597");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-01-30 14:57:13 +0530 (Mon, 30 Jan 2017)");
  script_name("Wireshark ASTERIX And DHCPv6 Dissector Multiple DoS Vulnerabilities - Windows");

  script_tag(name:"summary", value:"Wireshark is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An integer overflow error in the script 'epan/dissectors/packet-asterix.c'.

  - An integer overflow error in the script 'epan/dissectors/packet-dhcpv6.c'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause the application to enter an infinite loop and consume
  excessive CPU resources, resulting in denial-of-service conditions.");

  script_tag(name:"affected", value:"Wireshark version 2.2.0 to 2.2.3 and
  2.0.0 to 2.0.9 on Windows");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 2.2.4 or
  2.0.10 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-01.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95795");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95798");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-02.html");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=13344");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("wireshark/windows/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!wirversion = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:wirversion, test_version:"2.2.0", test_version2:"2.2.3"))
{
  fix = "2.2.4";
  VULN = TRUE;
}
else if(version_in_range(version:wirversion, test_version:"2.0.0", test_version2:"2.0.9"))
{
  fix = "2.0.10";
  VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:wirversion, fixed_version:fix);
  security_message(port:0, data:report);
  exit(0);
}
