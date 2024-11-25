# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901032");
  script_version("2024-07-23T05:05:30+0000");
  script_tag(name:"last_modification", value:"2024-07-23 05:05:30 +0000 (Tue, 23 Jul 2024)");
  script_tag(name:"creation_date", value:"2009-09-24 10:05:51 +0200 (Thu, 24 Sep 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-3241");
  script_name("Wireshark OpcUa Dissector Denial of Service Vulnerability - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_lin.nasl");
  script_mandatory_keys("wireshark/linux/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/36754");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36408");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2009-06.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2009-05.html");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3986");

  script_tag(name:"impact", value:"Successful exploitation could result in Denial of service condition.");

  script_tag(name:"affected", value:"Wireshark version 0.99.6 to 1.0.8, 1.2.0 to 1.2.1 on Linux.");

  script_tag(name:"insight", value:"The flaw is due to unspecified error in 'OpcUa' dissector which can be
  exploited by sending malformed OPCUA Service CallRequest packets.");

  script_tag(name:"solution", value:"Upgrade to Wireshark 1.0.9 or 1.2.2.");

  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

# Alert for Wireshark version 0.96.6 to 1.0.8 and 1.2.0 to 1.2.1
if(version_in_range(version:version, test_version:"0.99.6", test_version2:"1.0.8")||
   version_in_range(version:version, test_version:"1.2.0", test_version2:"1.2.1")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"1.0.9 or 1.2.2", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
