# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834281");
  script_version("2024-11-21T05:05:26+0000");
  script_cve_id("CVE-2024-40817", "CVE-2024-40776", "CVE-2024-40782", "CVE-2024-40779",
                "CVE-2024-40780", "CVE-2024-40785", "CVE-2024-40789", "CVE-2024-4558",
                "CVE-2024-40794", "CVE-2024-44185", "CVE-2024-44206");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-11-21 05:05:26 +0000 (Thu, 21 Nov 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-19 13:47:18 +0000 (Tue, 19 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-07-30 15:15:33 +0530 (Tue, 30 Jul 2024)");
  script_name("Apple Safari Security Update (HT214121)");

  script_tag(name:"summary", value:"Apple Safari is prone to multiple
  vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name: "insight" , value:"These vulnerabilities exist:

  - CVE-2024-40776: An use-after-free issue was addressed with improved memory management.

  - CVE-2024-40779: An out-of-bounds read was addressed with improved bounds checking.");

  script_tag(name: "impact" , value:"Successful exploitation allows an attacker
  to run arbitrary code, disclose information, bypass security restrictions,
  conduct spoofing and cause denial of service.");

  script_tag(name: "affected" , value:"Apple Safari prior to version 17.6");

  script_tag(name: "solution" , value:"Update to version 17.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT214121");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version", "ssh/login/osx_version");
  exit(0);
}

include("version_func.inc");
include("ssh_func.inc");
include("host_details.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || (osVer !~ "^12\." && osVer !~ "^13\.") || "Mac OS X" >!< osName)
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
safVer = infos["version"];
safPath = infos["location"];

if(version_is_less(version:safVer, test_version:"17.6")) {
  report = report_fixed_ver(installed_version:safVer, fixed_version:"17.6", install_path:safPath);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
