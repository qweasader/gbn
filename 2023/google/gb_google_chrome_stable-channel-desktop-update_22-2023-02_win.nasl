# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832013");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2023-0941", "CVE-2023-0927", "CVE-2023-0928", "CVE-2023-0929",
                "CVE-2023-0930", "CVE-2023-0931", "CVE-2023-0932", "CVE-2023-0933");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-28 02:17:00 +0000 (Tue, 28 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-23 13:48:09 +0530 (Thu, 23 Feb 2023)");
  script_name("Google Chrome Security Updates (stable-channel-desktop-update_22-2023-02) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Use after free in Prompts.

  - Use after free in Web Payments API.

  - Use after free in SwiftShader.

  - Use after free in Vulkan.

  - Heap buffer overflow in Video.

  - Use after free in Video.

  - Use after free in WebRTC.

  - Integer overflow in PDF.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to run arbitrary code, bypass security restrictions, conduct spoofing and
  cause a denial of service on affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to 110.0.5481.178 on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  110.0.5481.178 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/02/stable-channel-desktop-update_22.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"110.0.5481.178"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"110.0.5481.178", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
