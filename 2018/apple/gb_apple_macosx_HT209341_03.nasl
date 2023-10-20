# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814606");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2018-4431");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-05 16:08:00 +0000 (Fri, 05 Apr 2019)");
  script_tag(name:"creation_date", value:"2018-12-06 11:30:18 +0530 (Thu, 06 Dec 2018)");
  script_name("Apple MacOSX Security Updates(HT209341)-03");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a memory initialization
  issue.");

  script_tag(name:"impact", value:"Successful exploitation allows local attackers
  to read kernel memory.");

  script_tag(name:"affected", value:"Apple Mac OS X versions,
  10.13.x through 10.13.6 build 17G3025, 10.14.x through 10.14.1");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X 10.14.2 or later
  or apply appropriate patch for 10.13.x versions. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT209341");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.1[34]\.");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.1[34]\." || "Mac OS X" >!< osName){
  exit(0);
}

buildVer = get_kb_item("ssh/login/osx_build");

if(osVer =~ "^10\.13")
{
  if(version_in_range(version:osVer, test_version:"10.13", test_version2:"10.13.5")){
    fix = "Upgrade to latest OS release and apply patch from vendor";
  }

  else if(osVer == "10.13.6")
  {
    if(osVer == "10.13.6" && version_is_less(version:buildVer, test_version:"17G4015"))
    {
      fix = "Apply patch from vendor";
      osVer = osVer + " Build " + buildVer;
    }
  }
}

else if(osVer == "10.14.1" || osVer == "10.14"){
  fix = "10.14.2";
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);