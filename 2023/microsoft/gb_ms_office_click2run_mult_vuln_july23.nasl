# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832225");
  script_version("2023-10-13T05:06:10+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-33161", "CVE-2023-33162", "CVE-2023-33158", "CVE-2023-35311",
                "CVE-2023-33151", "CVE-2023-33148", "CVE-2023-33149", "CVE-2023-33150",
                "CVE-2023-33152", "CVE-2023-33153");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-11 18:15:00 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-12 10:51:38 +0530 (Wed, 12 Jul 2023)");
  script_name("Microsoft Office 365 (2016 Click-to-Run) Multiple Vulnerabilities (Jul23)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Office Click-to-Run update July 2023");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Microsoft Excel Information Disclosure and Remote Code Execution Vulnerabilities.

  - Microsoft Outlook Security Feature Bypass, Spoofing and Remote Code Execution
    Vulnerabilities.

  - Microsoft Office Elevation of Privilege Vulnerability.

  - Microsoft ActiveX Remote Code Execution Vulnerability.

  - Microsoft Office Graphics Remote Code Execution Vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker
  to conduct remote code execution, spoofing, disclose sensitive information,
  elevate privileges and bypass security restrictions on an affected system.");

  script_tag(name:"affected", value:"Microsoft Office 365 (2016 Click-to-Run).");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_office_click2run_detect_win.nasl");
  script_mandatory_keys("MS/Off/C2R/Ver", "MS/Office/C2R/UpdateChannel");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

officeVer = get_kb_item("MS/Off/C2R/Ver");
if(!officeVer || officeVer !~ "^16\.")
  exit(0);

UpdateChannel = get_kb_item("MS/Office/C2R/UpdateChannel");
officePath = get_kb_item("MS/Off/C2R/InstallPath");

## Version 2306 (Build 16529.20182)
## Monthly Channel renamed to Current Channel
if(UpdateChannel == "Monthly Channel") {
  if(version_is_less(version:officeVer, test_version:"16.0.16529.20182"))
    fix = "Version 2306 (Build 16529.20182)";
}
## Semi-Annual Channel (Targeted) renamed to Semi-Annual Enterprise Channel (Preview)
## Semi-Annual Enterprise Channel (Preview): Version 2302 (Build 16130.20644)
else if(UpdateChannel == "Semi-Annual Channel (Targeted)") {
  if(version_is_less(version:officeVer, test_version:"16.0.16130.20644"))
    fix = "Version 2302 (Build 16130.20580)";
}

## Semi-Annual Enterprise Channel: Version 2202 (Build 14931.21040)
## Semi-Annual Enterprise Channel: Version 2208 (Build 15601.20706)
## Semi-Annual Enterprise Channel: Version 2302 (Build 16130.20644)
## Semi-Annual Channel renamed to Semi-Annual Enterprise Channel
else if(UpdateChannel == "Semi-Annual Channel"){
  if(version_is_less(version:officeVer, test_version:"16.0.14931.21040")) {
    fix = "Version 2202 (Build 14931.21040)";
  }
  else if(version_in_range(version:officeVer, test_version:"16.0.15601.0", test_version2:"16.0.15601.20705")) {
    fix = "Version 2208 (Build 15601.20706)";
  }
  else if(version_in_range(version:officeVer, test_version:"16.0.16130.0", test_version2:"16.0.16130.20643")) {
    fix = "Version 2302 (Build 16130.20644)";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:officeVer, fixed_version:fix, install_path:officePath);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);