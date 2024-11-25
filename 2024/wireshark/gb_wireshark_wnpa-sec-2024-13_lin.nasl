# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834679");
  script_version("2024-10-18T15:39:59+0000");
  script_cve_id("CVE-2024-9781");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-10-18 15:39:59 +0000 (Fri, 18 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-10-11 10:45:33 +0530 (Fri, 11 Oct 2024)");
  script_name("Wireshark Security Update (wnpa-sec-2024-13) - Linux");

  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an AppleTalk and
  RELOAD Framing dissector crashes in Wireshark.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to conduct denial of service via packet injection or crafted capture file.");

  script_tag(name:"affected", value:"Wireshark version 4.4.0 and 4.2.0 through
  4.2.7 on Linux.");

  script_tag(name:"solution", value:"Update to version 4.4.1 or 4.2.8 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2024-13.html");
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_lin.nasl");
  script_mandatory_keys("wireshark/linux/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_equal(version:vers, test_version:"4.4.0")) {
  fix = "4.4.1";
}

if(version_in_range(version: vers, test_version: "4.2.0", test_version2: "4.2.7")) {
  fix = "4.2.8";
}

if(fix) {
  report = report_fixed_ver(installed_version: vers, fixed_version: fix, install_path: path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
