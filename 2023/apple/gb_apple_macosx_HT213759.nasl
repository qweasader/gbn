# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826990");
  script_version("2024-02-09T14:47:30+0000");
  script_cve_id("CVE-2023-23535", "CVE-2023-27940", "CVE-2023-27945", "CVE-2023-28191",
                "CVE-2023-32352", "CVE-2023-32355", "CVE-2023-32357", "CVE-2023-32360",
                "CVE-2023-32368", "CVE-2023-32369", "CVE-2023-32375", "CVE-2023-32380",
                "CVE-2023-32382", "CVE-2023-32384", "CVE-2023-32386", "CVE-2023-32387",
                "CVE-2023-32388", "CVE-2023-32392", "CVE-2023-32395", "CVE-2023-32397",
                "CVE-2023-32398", "CVE-2023-32403", "CVE-2023-32405", "CVE-2023-32407",
                "CVE-2023-32408", "CVE-2023-32410", "CVE-2023-32411", "CVE-2023-32412",
                "CVE-2023-32413", "CVE-2023-32383", "CVE-2023-32401", "CVE-2023-32428");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-30 07:04:00 +0000 (Fri, 30 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-05-22 11:55:29 +0530 (Mon, 22 May 2023)");
  script_name("Apple Mac OS X Security Update (HT213759)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to a code execution
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An improper redaction of sensitive information.

  - An improper entitlements.

  - An improper handling of temporary files.

  - An improper state and memory management.

  - An improper bounds checking and input validation.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  disclose sensitive information, escalate privileges and execute arbitrary code
  with kernel privileges on an affected system.");

  script_tag(name:"affected", value:"Apple Mac OS X Monterey versions 12.x before
  12.6.6.");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X Monterey version
  12.6.6 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213759");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");
  exit(0);
}

include("version_func.inc");
include("ssh_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName) {
  exit (0);
}

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^12\." || "Mac OS X" >!< osName) {
  exit(0);
}

if(version_is_less(version:osVer, test_version:"12.6.6")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"12.6.6");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
