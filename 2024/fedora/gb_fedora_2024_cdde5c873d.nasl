# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.99100100101599873100");
  script_cve_id("CVE-2024-50602");
  script_tag(name:"creation_date", value:"2024-11-19 04:08:45 +0000 (Tue, 19 Nov 2024)");
  script_version("2024-11-20T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-11-20 05:05:31 +0000 (Wed, 20 Nov 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-cdde5c873d)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-cdde5c873d");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-cdde5c873d");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2322195");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2322230");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mingw-expat' package(s) announced via the FEDORA-2024-cdde5c873d advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 2.6.4.

----

Backport fix for CVE-2024-50602.");

  script_tag(name:"affected", value:"'mingw-expat' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"mingw-expat", rpm:"mingw-expat~2.6.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-expat", rpm:"mingw32-expat~2.6.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-expat-debuginfo", rpm:"mingw32-expat-debuginfo~2.6.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-expat-static", rpm:"mingw32-expat-static~2.6.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-expat", rpm:"mingw64-expat~2.6.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-expat-debuginfo", rpm:"mingw64-expat-debuginfo~2.6.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-expat-static", rpm:"mingw64-expat-static~2.6.4~1.fc40", rls:"FC40"))) {
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
