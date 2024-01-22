# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826545");
  script_version("2023-12-15T16:10:08+0000");
  script_cve_id("CVE-2021-1821", "CVE-2021-30677", "CVE-2021-30748", "CVE-2021-30758",
                "CVE-2021-30759", "CVE-2021-30760", "CVE-2021-30765", "CVE-2021-30766",
                "CVE-2021-30768", "CVE-2021-30772", "CVE-2021-30774", "CVE-2021-30775",
                "CVE-2021-30776", "CVE-2021-30777", "CVE-2021-30778", "CVE-2021-30779",
                "CVE-2021-30780", "CVE-2021-30781", "CVE-2021-30782", "CVE-2021-30783",
                "CVE-2021-30784", "CVE-2021-30785", "CVE-2021-30786", "CVE-2021-30787",
                "CVE-2021-30788", "CVE-2021-30789", "CVE-2021-30790", "CVE-2021-30791",
                "CVE-2021-30792", "CVE-2021-30793", "CVE-2021-30795", "CVE-2021-30796",
                "CVE-2021-30797", "CVE-2021-30798", "CVE-2021-30799", "CVE-2021-30803",
                "CVE-2021-30805", "CVE-2021-30817", "CVE-2021-30871", "CVE-2021-31004",
                "CVE-2021-31006", "CVE-2021-3518");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-12-15 16:10:08 +0000 (Fri, 15 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-15 20:19:00 +0000 (Wed, 15 Sep 2021)");
  script_tag(name:"creation_date", value:"2022-09-22 23:16:40 +0530 (Thu, 22 Sep 2022)");
  script_name("Apple MacOSX Security Update(HT212602)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Multiple memory corruption issues.

  - Multiple out-of-bounds read issues.

  - Multiple out-of-bounds write issues.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities allow remote attackers to execute arbitrary code, bypass
  security restrictions, disclose sensitive information and cause a denial of
  service on affected system.");

  script_tag(name:"affected", value:"Apple Mac OS X Big Sur prior to
  version 11.5.");

  script_tag(name:"solution", value:"Upgrade to version 11.5 for macOS Big Sur 11.x.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT212603");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^11\.");
  exit(0);
}
include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^11\." || "Mac OS X" >!< osName){
  exit(0);
}

if(version_is_less(version:osVer, test_version:"11.5"))
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"11.5");
  security_message(data:report);
  exit(0);
}

exit(99);

