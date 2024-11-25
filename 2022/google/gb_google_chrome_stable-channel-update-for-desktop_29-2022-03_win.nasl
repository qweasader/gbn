# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.820049");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2022-1125", "CVE-2022-1127", "CVE-2022-1128", "CVE-2022-1129",
                "CVE-2022-1130", "CVE-2022-1131", "CVE-2022-1132", "CVE-2022-1133",
                "CVE-2022-1134", "CVE-2022-1135", "CVE-2022-1136", "CVE-2022-1137",
                "CVE-2022-1138", "CVE-2022-1139", "CVE-2022-1141", "CVE-2022-1142",
                "CVE-2022-1143", "CVE-2022-1144", "CVE-2022-1145", "CVE-2022-1146");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-27 16:13:00 +0000 (Wed, 27 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-03-31 10:35:16 +0530 (Thu, 31 Mar 2022)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_29-2022-03) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple use after free errors.

  - Multiple heap buffer overflow errors.

  - Type Confusion error in V8.

  - Inappropriate implementation errors.

  - An input validation error in WebOTP.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct denial of service, information disclosure and possibly code execution.");

  script_tag(name:"affected", value:"Google Chrome version prior to 100.0.4896.60
  on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 100.0.4896.60
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/03/stable-channel-update-for-desktop_29.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
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

if(version_is_less(version:vers, test_version:"100.0.4896.60"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"100.0.4896.60", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
