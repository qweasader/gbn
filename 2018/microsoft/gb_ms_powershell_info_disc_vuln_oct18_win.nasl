# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:powershell";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814090");
  script_version("2023-07-20T05:05:18+0000");
  script_cve_id("CVE-2018-8292");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-06 14:46:00 +0000 (Thu, 06 Dec 2018)");
  script_tag(name:"creation_date", value:"2018-10-11 11:56:04 +0530 (Thu, 11 Oct 2018)");
  script_name("Microsoft PowerShell Core Information Disclosure Vulnerability Oct18 (Windows)");

  script_tag(name:"summary", value:"This host is missing an important security
  update for PowerShell Core according to Microsoft security advisory
  CVE-2018-8292.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists when .NET Core when HTTP
  authentication information is inadvertently exposed in an outbound request that
  encounters an HTTP redirect.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to disclose sensitive information and use the information to further compromise
  the web application.");

  script_tag(name:"affected", value:"PowerShell Core versions 6.x prior to 6.1.0
  on Windows.");

  script_tag(name:"solution", value:"Update PowerShell Core to version 6.1.0 or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://github.com/PowerShell/PowerShell");
  script_xref(name:"URL", value:"https://github.com/PowerShell/Announcements/issues/7");
  script_xref(name:"URL", value:"https://github.com/PowerShell/PowerShell/issues/7981");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_powershell_core_detect_win.nasl");
  script_mandatory_keys("PowerShell/Win/Ver");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
psVer = infos['version'];
psPath = infos['location'];

if(psVer =~ "^6\." && version_is_less(version:psVer, test_version:"6.1.0")){
  fix = "6.1.0";
}

## Preview versions and release candidate versions
## v6.1.0-preview.4 = 6.1.0.4, v6.1.0-preview.1 = 6.1.0.1, v6.1.0-preview.2 = 6.1.0.2, v6.1.0-preview.3 = 6.1.0.3, 6.1.0-rc.1
affected = make_list('6.1.0.1', '6.1.0.2', '6.1.0.3', '6.1.0.4', '6.1.0-rc.1');
foreach version (affected)
{
  if(psVer == version){
   fix = "6.1.0";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:psVer, fixed_version:fix, install_path:psPath);
  security_message(data:report);
  exit(0);
}
exit(0);
