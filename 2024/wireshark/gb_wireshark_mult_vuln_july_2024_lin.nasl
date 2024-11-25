# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834257");
  script_version("2024-07-22T05:05:40+0000");
  script_cve_id("CVE-2024-0207", "CVE-2024-0210", "CVE-2024-0211");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-07-22 05:05:40 +0000 (Mon, 22 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-10 14:11:32 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-07-16 17:20:35 +0530 (Tue, 16 Jul 2024)");
  script_name("Wireshark Multiple Vulnerabilities (Jul 2024) - Linux");

  script_tag(name:"summary", value:"Wireshark is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-0207: HTTP3 dissector crash in Wireshark.

  - CVE-2024-0210: Zigbee TLV dissector crash in Wireshark.

  - CVE-2024-0211: DOCSIS dissector crash in Wireshark.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to cause denial of service via packet injection or crafted capture file.");

  script_tag(name:"affected", value:"Wireshark version 4.2.0 on Linux.");

  script_tag(name:"solution", value:"Update to version 4.2.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2024-03.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2024-04.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2024-05.html");
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_lin.nasl");
  script_mandatory_keys("wireshark/linux/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_equal(version: version, test_version: "4.2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.1", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
