# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.816893");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2020-7080", "CVE-2020-7081", "CVE-2020-7082", "CVE-2020-7083",
                "CVE-2020-7084", "CVE-2020-7085");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-23 13:53:00 +0000 (Thu, 23 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-23 12:01:55 +0530 (Thu, 23 Apr 2020)");
  script_name("Microsoft Office 365 (2016 Click-to-Run) Autodesk FBX Vulnerabilities (Apr 2020)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Office Click-to-Run updates.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A buffer overflow error in FBX's SDK.

  - A type confusion error in FBX's SDK.

  - A use-after-free error in FBX's SDK.

  - An integer overflow error in FBX's SDK.

  - A null pointer dereference error in FBX's SDK

  - The heap overflow error in FBX parser.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code and conduct a denial-of-service condition on the
  affected system.");

  script_tag(name:"affected", value:"Microsoft Office 365 (2016 Click-to-Run).");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/officeupdates/office365-proplus-security-updates");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
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

## Version 2003 (Build 12624.20466)
if(UpdateChannel == "Monthly Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.12624.20466"))
  {
    report = report_fixed_ver(installed_version:officeVer, fixed_version:"2003 (Build 12624.20466)", install_path:officePath);
    security_message(data:report);
    exit(0);
  }
}
exit(99);
