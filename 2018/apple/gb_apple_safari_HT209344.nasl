# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814601");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2018-4440", "CVE-2018-4439", "CVE-2018-4445", "CVE-2018-4437",
                "CVE-2018-4464", "CVE-2018-4441", "CVE-2018-4442", "CVE-2018-4443",
                "CVE-2018-4438");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-05 16:05:00 +0000 (Fri, 05 Apr 2019)");
  script_tag(name:"creation_date", value:"2018-12-06 10:43:13 +0530 (Thu, 06 Dec 2018)");
  script_name("Apple Safari Security Updates (HT209344)");

  script_tag(name:"summary", value:"Apple Safari is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A logic issue was addressed with improved state management.

  - A logic issue was addressed with improved validation.

  - 'Clear History and Website Data' did not clear the history.

  - Multiple memory corruption issues were addressed with improved memory handling.

  - A logic issue existed resulting in memory corruption.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to
  conduct spoofing attacks, arbitrary code execution and bypass security
  restrictions.");

  script_tag(name:"affected", value:"Apple Safari versions before 12.0.2");

  script_tag(name:"solution", value:"Upgrade to Apple Safari 12.0.2 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT209344");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version", "ssh/login/osx_name", "ssh/login/osx_version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

osName = get_kb_item("ssh/login/osx_name");
osVer = get_kb_item("ssh/login/osx_version");
if((!osName && "Mac OS X" >!< osName) || !osVer){
  exit (0);
}

if(version_in_range(version:osVer, test_version:"10.12", test_version2:"10.12.5"))
{
  fix = "Upgrade Apple Mac OS X to version 10.12.6 and Update Apple Safari to version 12.0.2";
  installedVer = "Apple Mac OS X " + osVer ;
}
else if(version_in_range(version:osVer, test_version:"10.13", test_version2:"10.13.5"))
{
  fix = "Upgrade Apple Mac OS X to version 10.13.6 and Update Apple Safari to version 12.0.2";
  installedVer = "Apple Mac OS X " + osVer ;
}
else if(osVer == "10.14")
{
  fix = "Upgrade Apple Mac OS X to version 10.14.1 and Update Apple Safari to version 12.0.2";
  installedVer = "Apple Mac OS X " + osVer ;
}

else
{
  if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
  safVer = infos['version'];
  safPath = infos['location'];

  if(version_is_less(version:safVer, test_version:"12.0.2"))
  {
    fix = "12.0.2";
    installedVer = "Apple Safari " + safVer ;
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:installedVer, fixed_version:fix, install_path:safPath);
  security_message(data:report);
  exit(0);
}

exit(99);
