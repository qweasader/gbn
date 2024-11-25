# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887386");
  script_cve_id("CVE-2024-6988", "CVE-2024-6989", "CVE-2024-7055", "CVE-2024-7532", "CVE-2024-7533", "CVE-2024-7534", "CVE-2024-7535", "CVE-2024-7536", "CVE-2024-7550");
  script_tag(name:"creation_date", value:"2024-08-15 04:04:24 +0000 (Thu, 15 Aug 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-12 18:32:08 +0000 (Mon, 12 Aug 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-0462a59d45)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-0462a59d45");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-0462a59d45");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2303050");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2303343");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2303344");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2303345");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2303348");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2303349");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2303350");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2303351");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2303352");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2303353");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2303354");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2303355");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2303356");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2303357");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2303359");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium' package(s) announced via the FEDORA-2024-0462a59d45 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 127.0.6533.99

 * Critical CVE-2024-7532: Out of bounds memory access in ANGLE
 * High CVE-2024-7533: Use after free in Sharing
 * High CVE-2024-7550: Type Confusion in V8
 * High CVE-2024-7534: Heap buffer overflow in Layout
 * High CVE-2024-7535: Inappropriate implementation in V8
 * High CVE-2024-7536: Use after free in WebAudio");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~127.0.6533.99~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~127.0.6533.99~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-common", rpm:"chromium-common~127.0.6533.99~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-headless", rpm:"chromium-headless~127.0.6533.99~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt5-ui", rpm:"chromium-qt5-ui~127.0.6533.99~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-qt6-ui", rpm:"chromium-qt6-ui~127.0.6533.99~1.fc40", rls:"FC40"))) {
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
