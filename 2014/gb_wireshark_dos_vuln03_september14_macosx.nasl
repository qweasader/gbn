# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804916");
  script_version("2024-07-22T05:05:40+0000");
  script_cve_id("CVE-2014-6421", "CVE-2014-6422");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"creation_date", value:"2014-09-24 16:26:02 +0530 (Wed, 24 Sep 2014)");

  script_name("Wireshark Denial of Service Vulnerability-03 (Sep 2014) - Mac OS X");

  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - the SDP dissector creates duplicate hashtables for a media channel.

  - the Use-after-free vulnerability in the SDP dissector.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attacker to cause denial of service attack

  - via a crafted packet to the RTP dissector.

  - via a crafted packet that leverages split memory ownership between
  the SDP and RTP dissectors.");

  script_tag(name:"affected", value:"Wireshark version 1.10.x before 1.10.10 on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Wireshark 1.10.10 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=9920");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69855");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69856");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2014-12.html");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("wireshark/macosx/detected");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!version = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:version, test_version:"1.10.0", test_version2:"1.10.9"))
{
  report = report_fixed_ver(installed_version:version, vulnerable_range:"1.10.0 - 1.10.9");
  security_message(port:0, data:report);
  exit(0);
}
