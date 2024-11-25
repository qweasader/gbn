# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832901");
  script_version("2024-04-05T05:05:37+0000");
  script_cve_id("CVE-2024-1580");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-04-05 05:05:37 +0000 (Fri, 05 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-03-28 17:06:07 +0530 (Thu, 28 Mar 2024)");
  script_name("Apple Mac OS X Security Update (HT214096)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to an out-of-bounds
  write vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an out-of-bounds
  write error in CoreMedia and WebRTC components of macOS Sonoma.");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to conduct arbitrary code execution.");

  script_tag(name:"affected", value:"Apple macOS Sonoma prior to version
  14.4.1");

  script_tag(name:"solution", value:"Update macOS Sonoma to version 14.4.1 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT214096");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^14\." || "Mac OS X" >!< osName) {
  exit(0);
}

if(version_is_less(version:osVer, test_version:"14.4.1")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"14.4.1");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
