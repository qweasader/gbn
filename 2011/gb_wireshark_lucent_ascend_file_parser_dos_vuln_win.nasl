# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802308");
  script_version("2024-07-22T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"creation_date", value:"2011-07-14 13:16:44 +0200 (Thu, 14 Jul 2011)");
  script_cve_id("CVE-2011-2597");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Wireshark Lucent/Ascend File Parser Denial of Service Vulnerability - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45086");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48506");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/68335");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2011-09.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_family("Denial of Service");
  script_mandatory_keys("wireshark/windows/detected");
  script_tag(name:"impact", value:"Successful exploitation allows attackers to cause the application to enter
  into an infinite loop and crash it.");
  script_tag(name:"affected", value:"Wireshark version 1.2.0 to 1.2.17, 1.4.0 to 1.4.7 and 1.6.0");
  script_tag(name:"insight", value:"The flaw is due to an error in Lucent/Ascend file parser when
  processing malicious packets.");
  script_tag(name:"solution", value:"Upgrade to Wireshark 1.2.18 or later");
  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version:version, test_version:"1.2.0", test_version2:"1.2.17") ||
   version_in_range(version:version, test_version:"1.4.0", test_version2:"1.4.7") ||
   version_is_equal(version:version, test_version:"1.6.0")) {
  security_message(port:0, data:"The target host was found to be vulnerable");
  exit(0);
}

exit(99);
