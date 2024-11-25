# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818843");
  script_version("2024-02-09T14:47:30+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2021-30876", "CVE-2021-30877", "CVE-2021-30879", "CVE-2021-30880",
                "CVE-2021-30907", "CVE-2021-30899", "CVE-2021-30917", "CVE-2021-30919",
                "CVE-2021-30881", "CVE-2021-30906", "CVE-2021-30824", "CVE-2021-30901",
                "CVE-2021-30821", "CVE-2021-30883", "CVE-2021-30909", "CVE-2021-30916",
                "CVE-2021-30910", "CVE-2021-30911", "CVE-2021-30868", "CVE-2021-30913",
                "CVE-2021-30912", "CVE-2021-30915", "CVE-2021-30908", "CVE-2021-30892",
                "CVE-2021-30833", "CVE-2021-30844", "CVE-2021-30900", "CVE-2021-30903",
                "CVE-2021-30905", "CVE-2021-30922", "CVE-2021-30926");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-02 13:59:00 +0000 (Tue, 02 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-10-28 19:41:37 +0530 (Thu, 28 Oct 2021)");
  script_name("Apple Mac OS X Security Update (HT212872)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple out-of-bounds read errors.

  - Multiple memory corruption errors.

  - An improper state management.

  - An inherited permissions issue.

  - A logic issue due to improper state management.

  - Multiple input validation errors.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution, privilege escalation and information
  disclosure etc.");

  script_tag(name:"affected", value:"Apple Mac OS X Big Sur versions 11.x before
  11.6.1.");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X Big Sur version
  11.6.1 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT212872");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");
  exit(0);
}
include("version_func.inc");
include("ssh_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName){
  exit (0);
}

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^11\." || "Mac OS X" >!< osName){
  exit(0);
}

if(version_in_range(version:osVer, test_version:"11.0", test_version2:"11.6.0"))
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"11.6.1");
  security_message(data:report);
  exit(0);
}
exit(99);
