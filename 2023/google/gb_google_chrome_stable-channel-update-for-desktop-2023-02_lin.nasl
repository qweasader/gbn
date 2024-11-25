# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821361");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2023-0696", "CVE-2023-0697", "CVE-2023-0698", "CVE-2023-0699",
                "CVE-2023-0700", "CVE-2023-0701", "CVE-2023-0702", "CVE-2023-0703",
                "CVE-2023-0704", "CVE-2023-0705");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-16 15:16:00 +0000 (Thu, 16 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-08 15:39:28 +0530 (Wed, 08 Feb 2023)");
  script_name("Google Chrome Security Updates (stable-channel-update-for-desktop-2023-02) - Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Type Confusion in V8.

  - Inappropriate implementation in Full screen mode.

  - Out of bounds read in WebRTC.

  - Use after free in GPU.

  - Inappropriate implementation in Download.

  - Heap buffer overflow in WebUI.

  - Type Confusion in Data Transfer.

  - Type Confusion in DevTools.

  - Insufficient policy enforcement in DevTools.

  - Integer overflow in Core.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, bypass security restrictions,
  conduct spoofing and cause a denial of service on affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to 110.0.5481.77 on Linux");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  110.0.5481.77 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/02/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"110.0.5481.77"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"110.0.5481.77", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
