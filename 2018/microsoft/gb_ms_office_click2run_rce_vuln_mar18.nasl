# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812997");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2018-0841");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-03-23 11:36:25 +0530 (Fri, 23 Mar 2018)");
  script_name("Microsoft Office 2016 Click-to-Run (C2R) Remote Code Execution Vulnerability (Mar 2018)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Office Click-to-Run updates.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in the
  Microsoft Excel because it fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code in the context of the current user.");

  script_tag(name:"affected", value:"Microsoft Office 2016 Click-to-Run.");

  script_tag(name:"solution", value:"Upgrade to latest version of Microsoft Office
  2016 Click-to-Run with respect to update channel used.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/office/mt465751");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102957");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0841");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
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

##1801 (Build 9001.2171)
if(UpdateChannel == "Monthly Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.9001.2171")){
    fix = "1801 (Build 9001.2171)";
  }
}
##1708 (Build 8431.2215)
else if(UpdateChannel == "Semi-Annual Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.8431.2215")){
    fix = "1708 (Build 8431.2215)";
  }
}
##Version 1708 (Build 8431.2215)
else if(UpdateChannel == "Semi-Annual Channel (Targeted)")
{
  if(version_is_less(version:officeVer, test_version:"16.0.8431.2215)")){
    fix = "1708 (Build 8431.2215)";
  }
}
##1705 (Build 8201.2258)
else if(UpdateChannel == "Deferred Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.8201.2258")){
    fix = "1705 (Build 8201.2258)";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:officeVer, fixed_version:fix, install_path:officePath);
  security_message(data:report);
  exit(0);
}
exit(0);
