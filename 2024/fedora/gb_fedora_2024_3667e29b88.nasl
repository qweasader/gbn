# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887400");
  script_cve_id("CVE-2023-4322", "CVE-2023-47016", "CVE-2023-5686");
  script_tag(name:"creation_date", value:"2024-08-23 04:04:17 +0000 (Fri, 23 Aug 2024)");
  script_version("2024-09-13T15:40:36+0000");
  script_tag(name:"last_modification", value:"2024-09-13 15:40:36 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-22 20:41:23 +0000 (Tue, 22 Aug 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2024-3667e29b88)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-3667e29b88");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-3667e29b88");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2251066");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2303807");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2303875");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2304300");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2304301");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'iaito, radare2' package(s) announced via the FEDORA-2024-3667e29b88 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Bump to version 5.9.4");

  script_tag(name:"affected", value:"'iaito, radare2' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"iaito", rpm:"iaito~5.9.4~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iaito-debuginfo", rpm:"iaito-debuginfo~5.9.4~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iaito-debugsource", rpm:"iaito-debugsource~5.9.4~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radare2", rpm:"radare2~5.9.4~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radare2-common", rpm:"radare2-common~5.9.4~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radare2-debuginfo", rpm:"radare2-debuginfo~5.9.4~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radare2-debugsource", rpm:"radare2-debugsource~5.9.4~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radare2-devel", rpm:"radare2-devel~5.9.4~1.fc39", rls:"FC39"))) {
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
