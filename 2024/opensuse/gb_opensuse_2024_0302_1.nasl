# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856478");
  script_version("2024-09-25T05:06:11+0000");
  script_cve_id("CVE-2024-8636", "CVE-2024-8637", "CVE-2024-8638", "CVE-2024-8639");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-12 13:35:03 +0000 (Thu, 12 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-09-17 04:00:27 +0000 (Tue, 17 Sep 2024)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2024:0302-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0302-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/X5R3A7VNTZ3JKV7YDW56C7TEUFBJLNKE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2024:0302-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

     Chromium 128.0.6613.137 (released 2024-09-10) (boo#1230391)

  * CVE-2024-8636: Heap buffer overflow in Skia

  * CVE-2024-8637: Use after free in Media Router

  * CVE-2024-8638: Type Confusion in V8

  * CVE-2024-8639: Use after free in Autofill");

  script_tag(name:"affected", value:"'chromium' package(s) on openSUSE Backports SLE-15-SP5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSEBackportsSLE-15-SP5") {

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~128.0.6613.137~bp155.2.114.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~128.0.6613.137~bp155.2.114.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);