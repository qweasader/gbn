# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886774");
  script_cve_id("CVE-2024-3156", "CVE-2024-3157", "CVE-2024-3158", "CVE-2024-3159", "CVE-2024-3515", "CVE-2024-3516");
  script_tag(name:"creation_date", value:"2024-05-27 10:47:02 +0000 (Mon, 27 May 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-26 15:59:59 +0000 (Fri, 26 Apr 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-4d2d73ab31)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-4d2d73ab31");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-4d2d73ab31");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2274472");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium' package(s) announced via the FEDORA-2024-4d2d73ab31 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"update to 123.0.6312.122

 * High CVE-2024-3157: Out of bounds write in Compositing
 * High CVE-2024-3516: Heap buffer overflow in ANGLE
 * High CVE-2024-3515: Use after free in Dawn


----

update to 123.0.6312.105

 * High CVE-2024-3156: Inappropriate implementation in V8
 * High CVE-2024-3158: Use after free in Bookmarks
 * High CVE-2024-3159: Out of bounds memory access in V8");

  script_tag(name:"affected", value:"'chromium' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~123.0.6312.122~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~123.0.6312.122~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-common", rpm:"chromium-common~123.0.6312.122~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-headless", rpm:"chromium-headless~123.0.6312.122~1.fc40", rls:"FC40"))) {
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
