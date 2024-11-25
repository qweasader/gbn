# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834253");
  script_version("2024-09-11T05:05:55+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-07-12 16:32:10 +0530 (Fri, 12 Jul 2024)");
  script_name("Wireshark Security Update (wnpa-sec-2024-10) - Mac OS X");

  script_cve_id("CVE-2024-8645");

  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an issue in SPRT
  Dissector.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to make Wireshark crash by injecting a malformed packet onto the wire or by
  convincing someone to read a malformed packet trace file.");

  script_tag(name:"affected", value:"Wireshark version 4.0.0 through 4.0.15
  and 4.2.0 through 4.2.5 on Mac OS X.");

  script_tag(name:"solution", value:"Update to version 4.0.16 or 4.2.6 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2024-10.html");
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("wireshark/macosx/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version:version, test_version:"4.0.0", test_version2:"4.0.15")) {
  fix = "4.0.16";
}

else if(version_in_range(version:version, test_version:"4.2.0", test_version2:"4.2.5")) {
  fix = "4.2.6";
}

if(fix) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
