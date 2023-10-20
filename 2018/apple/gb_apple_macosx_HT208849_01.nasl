# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813510");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2018-4237", "CVE-2018-4236", "CVE-2018-4235", "CVE-2018-4234",
                "CVE-2018-4230", "CVE-2018-4141", "CVE-2018-4219", "CVE-2018-4241",
                "CVE-2018-4243", "CVE-2018-4251", "CVE-2018-4253", "CVE-2018-7584",
                "CVE-2018-4184", "CVE-2018-4228", "CVE-2018-4229", "CVE-2018-4221",
                "CVE-2018-4223", "CVE-2018-4224", "CVE-2018-4226", "CVE-2018-4227",
                "CVE-2018-4202", "CVE-2018-4242", "CVE-2018-4240", "CVE-2018-4196",
                "CVE-2018-4198", "CVE-2018-4225");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-06-04 14:08:42 +0530 (Mon, 04 Jun 2018)");
  script_name("Apple MacOSX Security Updates(HT208849)-01");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A logic issue in validation.

  - A memory corruption issue in memory handling.

  - An injection issue in input validation.

  - A race condition in locking.

  - A validation issue in input sanitization.

  - A type confusion issue in memory handling.

  - A buffer overflow issue in bounds checking.

  - A device configuration issue in configuration.

  - An out-of-bounds read issue leading to the disclosure of kernel memory.

  - A sandbox issue in handling of microphone access.

  - An issue in parsing entitlement plists.

  - An issue in the handling of S-MIME certificaties.

  - An authorization issue in state management.

  - An issue in the handling of encrypted Mail.

  - An input validation issue.

  - A memory corruption vulnerability in improved locking.

  - An information disclosure issue in Accessibility Framework.

  - A validation issue existed in the handling of text.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain elevated privileges, execute arbitrary code, conduct
  impersonation attacks, read restricted memory, modify the EFI flash memory
  region, circumvent sandbox restrictions, read a persistent account identifier,
  read kernel memory, view sensitive user information, exfiltrate the contents
  of S/MIME- encrypted e-mail, spoof password prompts in iBooks and cause denial
  of service.");

  script_tag(name:"affected", value:"Apple Mac OS X versions,
  10.13.x through 10.13.4");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X 10.13.5 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT208849");
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
if(!osVer || osVer !~ "^10\.13" || "Mac OS X" >!< osName)
  exit(0);

if(version_is_less(version:osVer, test_version:"10.13.5")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"10.13.5");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
