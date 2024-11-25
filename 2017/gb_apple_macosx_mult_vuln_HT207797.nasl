# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810986");
  script_version("2024-02-16T14:37:06+0000");
  script_cve_id("CVE-2017-6988", "CVE-2017-6978", "CVE-2017-2502", "CVE-2017-2497",
                "CVE-2017-6981", "CVE-2017-6986", "CVE-2017-2503", "CVE-2017-2545",
                "CVE-2017-2494", "CVE-2017-2501", "CVE-2017-2507", "CVE-2017-2509",
                "CVE-2017-6987", "CVE-2017-2542", "CVE-2017-2543", "CVE-2017-6985",
                "CVE-2017-2534", "CVE-2017-6977", "CVE-2017-2513", "CVE-2017-2518",
                "CVE-2017-2520", "CVE-2017-2519", "CVE-2017-6983", "CVE-2017-6991");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-16 14:37:06 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-05-16 15:13:02 +0530 (Tue, 16 May 2017)");
  script_name("Apple Mac OS X Multiple Vulnerabilities (HT207797)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A certificate validation issue existed in EAP-TLS when a certificate
    changed.

  - Multiple memory corruption issues.

  - Multiple input validation issues.

  - A URL handling issue due to poor state management.

  - An issue existed within the path validation logic for symlinks.

  - A race condition due to poor locking mechanism.

  - An access issue due to poor sandbox restrictions.

  - A use after free issue due to poor state management.

  - A buffer overflow issue due to poor memory handling.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to obtain sensitive information, gain extra privileges, execute arbitrary code,
  and bypass security restrictions.");

  script_tag(name:"affected", value:"Apple Mac OS X version 10.12.x before
  10.12.5");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X version
  10.12.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT207797");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.12");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer){
  exit(0);
}

if("Mac OS X" >< osName && osVer =~ "^10\.12")
{
  if(version_in_range(version:osVer, test_version:"10.12", test_version2:"10.12.4"))
  {
    report = report_fixed_ver(installed_version:osVer, fixed_version:"10.12.5");
    security_message(data:report);
    exit(0);
  }
}

exit(99);
