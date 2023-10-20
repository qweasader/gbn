# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813318");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2018-4206", "CVE-2018-4187");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-17 15:52:00 +0000 (Tue, 17 Jul 2018)");
  script_tag(name:"creation_date", value:"2018-04-25 11:47:33 +0530 (Wed, 25 Apr 2018)");
  script_name("Apple MacOSX Security Updates(HT208742)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A memory corruption issue related to improper error handling.

  - A spoofing issue existed in the handling of URLs.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain elevated privileges and conduct UI spoofing.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.13.x through
  10.13.4");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X 10.13.4 and
  apply the appropriate security update. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208742");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.13");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.13" || "Mac OS X" >!< osName){
  exit(0);
}

##https://en.wikipedia.org/wiki/MacOS_High_Sierra
if(osVer == "10.13.4")
{
  buildVer = get_kb_item("ssh/login/osx_build");
  if(!buildVer){
    exit(0);
  }
  if(version_is_less(version:buildVer, test_version:"17E202"))
  {
    fix = "Apply security update from vendor";
    osVer = osVer + " Build " + buildVer;
  }
}
else if(version_is_less(version:osVer, test_version:"10.13.4")){
  fix = "Upgrade to latest OS release 10.13.4 and apply security update from vendor";
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);
