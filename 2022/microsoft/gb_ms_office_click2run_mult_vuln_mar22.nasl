# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818973");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2022-24510", "CVE-2022-24509", "CVE-2022-24461", "CVE-2022-24511",
                "CVE-2022-24462");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-14 18:52:00 +0000 (Mon, 14 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-10 05:03:57 +0000 (Thu, 10 Mar 2022)");
  script_name("Microsoft Office 365 (2016 Click-to-Run) Multiple Vulnerabilities (Mar 2022)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Office Click-to-Run updates");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple remote code execution vulnerabilities in Microsoft Office Visio.

  - A tampering vulnerability in Microsoft Office Word.

  - A security bypass vulnerability in Microsoft Word.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct remote code execution and gain privileged access.");

  script_tag(name:"affected", value:"Microsoft Office 365 (2016 Click-to-Run).");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_office_click2run_detect_win.nasl");
  script_mandatory_keys("MS/Off/C2R/Ver", "MS/Office/C2R/UpdateChannel");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

officeVer = get_kb_item("MS/Off/C2R/Ver");
if(!officeVer || officeVer !~ "^16\."){
  exit(0);
}

UpdateChannel = get_kb_item("MS/Office/C2R/UpdateChannel");
officePath = get_kb_item("MS/Off/C2R/InstallPath");

## Version 2202 (Build 14931.20132)
## Monthly Channel renamed to Current Channel
if(UpdateChannel == "Monthly Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.14931.20132")){
    fix = "Version 2202 (Build 14931.20132)";
  }
}

## Semi-Annual Channel (Targeted) renamed to Semi-Annual Enterprise Channel (Preview)
## Semi-Annual Enterprise Channel (Preview): Version 2202 (Build 14931.20132)
else if(UpdateChannel == "Semi-Annual Channel (Targeted)")
{
  if(version_is_less(version:officeVer, test_version:"16.0.14931.20132")){
    fix = "Version 2202 (Build 14931.20132)";
  }
}

##Semi-Annual Enterprise Channel: Version 2108 (Build 14326.20852)
##Semi-Annual Enterprise Channel: Version 2102 (Build 13801.21214)
else if(UpdateChannel == "Semi-Annual Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.13801.21214")){
    fix = "2102 (Build 13801.21214)";
  }
  else if(version_in_range(version:officeVer, test_version:"16.0.14326", test_version2:"16.0.14326.20851")){
    fix = "2108 (Build 14326.20852)";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:officeVer, fixed_version:fix, install_path:officePath);
  security_message(data:report);
  exit(0);
}
exit(99);
