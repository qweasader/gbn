# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832112");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2023-29532", "CVE-2023-29533", "CVE-2023-29535", "CVE-2023-29536",
                "CVE-2023-0547", "CVE-2023-29479", "CVE-2023-29539", "CVE-2023-29542",
                "CVE-2023-29545", "CVE-2023-1945", "CVE-2023-29548", "CVE-2023-29550",
                "CVE-2023-1999");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-27 08:51:00 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-04-12 13:57:54 +0530 (Wed, 12 Apr 2023)");
  script_name("Mozilla Thunderbird Security Advisory (MFSA2023-15) - Windows");

  script_tag(name:"summary", value:"Thunderbird is prone to a security bypass
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Mozilla Maintenance Service Write-lock bypass

  - Fullscreen notification obscured

  - Double-free in libwebp

  - Potential Memory Corruption following Garbage Collector compaction

  - Invalid free from JavaScript code

  - evocation status of S/Mime recipient certificates was not checked

  - Hang when processing certain OpenPGP messages

  - Content-Disposition filename truncation leads to Reflected File Download

  - Bypass of file download extension restrictions

  - Windows Save As dialog resolved environment variables

  - Memory Corruption in Safe Browsing Code

  - Incorrect optimization result on ARM64

  - Memory safety bugs fixed in Thunderbird 102.10");

  script_tag(name:"impact", value:"Successful exploitation allow attackers to
  disclose sensitive information, execute arbitrary code and cause denial of
  service condition.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before 102.10 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 102.10
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-15/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
tbVer = infos['version'];
tbPath = infos['location'];

if(version_is_less(version:tbVer, test_version:"102.10"))
{
  report = report_fixed_ver(installed_version:tbVer, fixed_version:"102.10", install_path:tbPath);
  security_message(data:report);
  exit(0);
}
