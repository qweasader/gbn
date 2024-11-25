# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817089");
  script_version("2024-02-16T05:06:55+0000");
  script_cve_id("CVE-2020-1240", "CVE-2020-1342", "CVE-2020-1445", "CVE-2020-1446", "CVE-2020-1458");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-15 20:07:00 +0000 (Wed, 15 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-28 10:34:07 +0530 (Tue, 28 Jul 2020)");
  script_name("Microsoft Office Multiple Vulnerabilities (Jul 2020) - Mac OS X");

  script_tag(name:"summary", value:"This host is missing an important security
  update for Microsoft Office 2016 and Office 2019 on Mac OS X according to
  Microsoft security updates July 2020");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple errors in Microsoft Excel because it fails to properly handle objects in memory.

  - An error in Microsoft Office software when it fails to properly handle objects
    in memory.

  - An error in Microsoft Outlook when Office fails to enforce security settings
    configured on a system.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code and bypass security restrictions.");

  script_tag(name:"affected", value:"Microsoft Office 2016 and Office 2019 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to latest version for Microsoft
  Office 2016 and Office 2019. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/officeupdates/release-notes-office-2016-mac");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-gb/officeupdates/release-notes-office-for-mac");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_office_detect_macosx.nasl");
  script_mandatory_keys("MS/Office/MacOSX/Ver");
  exit(0);
}

include("version_func.inc");

if(!offVer = get_kb_item("MS/Office/MacOSX/Ver")){
  exit(0);
}

if(offVer =~ "^1[56]\.")
{
  if(version_is_less_equal(version:offVer, test_version:"16.16.23")){
    fix = "Apply latest update";
  }
  else if(version_in_range(version:offVer, test_version:"16.17.0", test_version2:"16.38")){
    fix = "Apply latest update";
  }

  if(fix)
  {
    report = report_fixed_ver(installed_version:offVer, fixed_version:fix);
    security_message(data:report);
    exit(0);
  }
}
exit(0);
