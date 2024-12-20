# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826779");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2023-0128", "CVE-2023-0129", "CVE-2023-0130", "CVE-2023-0131",
                "CVE-2023-0132", "CVE-2023-0133", "CVE-2023-0134", "CVE-2023-0135",
                "CVE-2023-0136", "CVE-2023-0137", "CVE-2023-0138", "CVE-2023-0139",
                "CVE-2023-0140", "CVE-2023-0141");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-13 14:08:00 +0000 (Fri, 13 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-11 16:34:10 +0530 (Wed, 11 Jan 2023)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop-2023-01) - Mac OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Use after free in Overview Mode.

  - Heap buffer overflow in Network Service.

  - Inappropriate implementation in Fullscreen API.

  - Inappropriate implementation in iframe Sandbox.

  - Inappropriate implementation in Permission prompts.

  - Use after free in Cart.

  - Heap buffer overflow in Platform Apps.

  - Heap buffer overflow in libphonenumber.

  - Insufficient validation of untrusted input in Downloads.

  - Inappropriate implementation in File System API.

  - Insufficient policy enforcement in CORS.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, bypass security restrictions, conduct spoofing
  and cause a denial of service on affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  109.0.5414.87 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  109.0.5414.87 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2023/01/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"109.0.5414.87"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"109.0.5414.87", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
