# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.1017990970100876");
  script_cve_id("CVE-2024-48241");
  script_tag(name:"creation_date", value:"2024-11-11 04:08:36 +0000 (Mon, 11 Nov 2024)");
  script_version("2024-11-12T05:05:34+0000");
  script_tag(name:"last_modification", value:"2024-11-12 05:05:34 +0000 (Tue, 12 Nov 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-e7c0a0d876)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-e7c0a0d876");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-e7c0a0d876");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2318484");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2319076");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2322791");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2322792");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2322793");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2322794");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2322795");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'iaito, radare2' package(s) announced via the FEDORA-2024-e7c0a0d876 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"fix CVE-2024-48241");

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

  if(!isnull(res = isrpmvuln(pkg:"iaito", rpm:"iaito~5.9.6~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iaito-debuginfo", rpm:"iaito-debuginfo~5.9.6~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"iaito-debugsource", rpm:"iaito-debugsource~5.9.6~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radare2", rpm:"radare2~5.9.6~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radare2-common", rpm:"radare2-common~5.9.6~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radare2-debuginfo", rpm:"radare2-debuginfo~5.9.6~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radare2-debugsource", rpm:"radare2-debugsource~5.9.6~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radare2-devel", rpm:"radare2-devel~5.9.6~1.fc39", rls:"FC39"))) {
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
