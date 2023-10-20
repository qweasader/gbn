# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805393");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-3814", "CVE-2015-3812", "CVE-2015-3811");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-06-01 17:26:23 +0530 (Mon, 01 Jun 2015)");
  script_name("Wireshark Multiple Denial-of-Service Vulnerabilities-02 June15 (Windows)");

  script_tag(name:"summary", value:"Wireshark is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The X11 dissector that is triggered when handling a specially crafted
  packet, which can result in a memory leak.

  - 'epan/dissectors/packet-wcp.c' in the WCP dissector improperly refers to
  previously processed bytes.

  - The IEEE 802.11 dissector that is triggered when handling a malformed
  packet, which can result in an infinite loop.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct denial of service attack.");

  script_tag(name:"affected", value:"Wireshark version 1.10.x before 1.10.14
  and 1.12.x before 1.12.5 on Windows");

  script_tag(name:"solution", value:"Upgrade to version 1.10.14 or 1.12.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2015-18.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74637");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74635");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/74631");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!wirversion = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:wirversion, test_version:"1.10.0", test_version2:"1.10.13"))
{
  fix = "1.10.14";
  VULN = TRUE;
}


if(version_in_range(version:wirversion, test_version:"1.12.0", test_version2:"1.12.4"))
{
  fix = "1.12.5";
  VULN = TRUE;
}

if(VULN)
{
  report = 'Installed Version: ' + wirversion + '\n' +
           'Fixed Version:     ' + fix + '\n';
  security_message(data:report);
  exit(0);
}


