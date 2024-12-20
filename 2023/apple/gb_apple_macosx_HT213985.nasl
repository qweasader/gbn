# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832610");
  script_version("2024-06-21T05:05:42+0000");
  script_cve_id("CVE-2023-40449", "CVE-2023-42854", "CVE-2023-40413", "CVE-2023-42844",
                "CVE-2023-41077", "CVE-2023-40416", "CVE-2023-40423", "CVE-2023-38403",
                "CVE-2023-42849", "CVE-2023-42856", "CVE-2023-40401", "CVE-2023-42841",
                "CVE-2023-40421", "CVE-2023-41254", "CVE-2023-41975", "CVE-2023-42823",
                "CVE-2023-42848", "CVE-2023-42942", "CVE-2023-42877", "CVE-2023-42859",
                "CVE-2023-42840", "CVE-2023-42889", "CVE-2023-42853", "CVE-2023-42860",
                "CVE-2023-42873", "CVE-2023-36191", "CVE-2023-42858");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-21 05:05:42 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-02 18:00:00 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-10-27 13:07:18 +0530 (Fri, 27 Oct 2023)");
  script_name("Apple Mac OS X Security Update (HT213985)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Improper checks.

  - Improper handling of caches.

  - Existence of vulnerable code.

  - An improper input validation.

  - An improper memory handling.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct arbitrary code execution, denial of service, information disclosure.");

  script_tag(name:"affected", value:"Apple macOS Ventura prior to version 13.6.1");

  script_tag(name:"solution", value:"Upgrade to version 13.6.1 for macOS Ventura.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT213985");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^13\.");
  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^13\." || "Mac OS X" >!< osName) {
  exit(0);
}

if(version_is_less(version:osVer, test_version:"13.6.1")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"13.6.1");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
