# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804018");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2013-5717");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-09-27 10:45:37 +0530 (Fri, 27 Sep 2013)");
  script_name("Wireshark Denial of Service Vulnerability Sep13 (Windows)");

  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 1.10.2 or later.");

  script_tag(name:"insight", value:"Flaw is due to an error in the Bluetooth HCI ACL dissector (dissectors/packet-bthci_acl.c).");

  script_tag(name:"affected", value:"Wireshark version 1.10.x before 1.10.2 on Windows.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a DoS (Denial of Service)
  and potentially compromise a vulnerable system.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54765");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62322");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2013-55.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!sharkVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(sharkVer  =~ "^(1\.10)")
{
  if(version_is_less(version:sharkVer, test_version:"1.10.2"))
  {
    report = report_fixed_ver(installed_version:sharkVer, fixed_version:"1.10.2");
    security_message(port: 0, data: report);
    exit(0);
  }
}
