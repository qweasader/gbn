# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903022");
  script_version("2024-07-22T05:05:40+0000");
  script_cve_id("CVE-2011-1590");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"creation_date", value:"2012-04-26 10:21:42 +0530 (Thu, 26 Apr 2012)");
  script_name("Wireshark X.509if Dissector Denial of Service Vulnerability - Mac OS X");

  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("wireshark/macosx/detected");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause a denial of service
  via crafted '.pcap' file.");
  script_tag(name:"affected", value:"Wireshark version 1.2.0 through 1.2.15
  Wireshark version 1.4.0 through 1.4.4");
  script_tag(name:"insight", value:"The flaw is caused by an error in the 'X.509if' dissector when processing
  malformed data, which could be exploited to crash an affected application.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.4.5 or 1.2.16 or later.");
  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1025388");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47392");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/1022");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version:version, test_version:"1.2.0", test_version2:"1.2.15")||
   version_in_range(version:version, test_version:"1.4.0", test_version2:"1.4.4")) {
  security_message(port:0, data:"The target host was found to be vulnerable");
  exit(0);
}

exit(99);
