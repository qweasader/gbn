# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832110");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2023-29532", "CVE-2023-29533", "CVE-2023-29535", "CVE-2023-29536",
                "CVE-2023-29537", "CVE-2023-29538", "CVE-2023-29539", "CVE-2023-29540",
                "CVE-2023-29542", "CVE-2023-29543", "CVE-2023-29544", "CVE-2023-29545",
                "CVE-2023-29547", "CVE-2023-29548", "CVE-2023-29549", "CVE-2023-29550",
                "CVE-2023-29551", "CVE-2023-1999");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-27 08:51:00 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-04-12 13:17:11 +0530 (Wed, 12 Apr 2023)");
  script_name("Mozilla Firefox Security Advisory (MFSA2023-13) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Mozilla Maintenance Service Write-lock bypass

  - Fullscreen notification obscured

  - Double-free in libwebp

  - Potential Memory Corruption following Garbage Collector compaction

  - Invalid free from JavaScript code

  - Data Races in font initialization code

  - Directory information could have been leaked to WebExtensions

  - Content-Disposition filename truncation leads to Reflected File Download

  - Iframe sandbox bypass using redirects and sourceMappingUrls

  - Bypass of file download extension restrictions

  - Use-after-free in debugging APIs

  - Memory Corruption in garbage collector

  - Windows Save As dialog resolved environment variables

  - Secure document cookie could be spoofed with insecure cookie");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute arbitrary code, disclose sensitive information and
  conduct spoofing attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  112 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 112
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-13/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"112"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"112", install_path:path);
  security_message(data:report);
  exit(0);
}
