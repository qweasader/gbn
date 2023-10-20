# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0366");
  script_cve_id("CVE-2017-13721", "CVE-2017-13723");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-04 02:29:00 +0000 (Sun, 04 Feb 2018)");

  script_name("Mageia: Security Advisory (MGASA-2017-0366)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(5|6)");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0366");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0366.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21820");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/10/04/10");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'x11-server' package(s) announced via the MGASA-2017-0366 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In Xext/shm, the shmseg resource id can belong to a non-existing client
and abort X server with FatalError 'client not in use', or overwrite
existing segment of another existing client (CVE-2017-13721).

Generating strings for XKB data used a single shared static buffer,
which offered several opportunities for errors when strings end up
longer than anticipated (CVE-2017-13723).");

  script_tag(name:"affected", value:"'x11-server' package(s) on Mageia 5, Mageia 6.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"x11-server", rpm:"x11-server~1.16.4~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-common", rpm:"x11-server-common~1.16.4~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-devel", rpm:"x11-server-devel~1.16.4~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-source", rpm:"x11-server-source~1.16.4~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-xdmx", rpm:"x11-server-xdmx~1.16.4~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-xephyr", rpm:"x11-server-xephyr~1.16.4~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-xfake", rpm:"x11-server-xfake~1.16.4~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-xfbdev", rpm:"x11-server-xfbdev~1.16.4~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-xnest", rpm:"x11-server-xnest~1.16.4~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-xorg", rpm:"x11-server-xorg~1.16.4~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-xvfb", rpm:"x11-server-xvfb~1.16.4~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-xwayland", rpm:"x11-server-xwayland~1.16.4~2.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"x11-server", rpm:"x11-server~1.19.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-common", rpm:"x11-server-common~1.19.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-devel", rpm:"x11-server-devel~1.19.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-source", rpm:"x11-server-source~1.19.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-xdmx", rpm:"x11-server-xdmx~1.19.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-xephyr", rpm:"x11-server-xephyr~1.19.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-xfake", rpm:"x11-server-xfake~1.19.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-xfbdev", rpm:"x11-server-xfbdev~1.19.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-xnest", rpm:"x11-server-xnest~1.19.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-xorg", rpm:"x11-server-xorg~1.19.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-xvfb", rpm:"x11-server-xvfb~1.19.4~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"x11-server-xwayland", rpm:"x11-server-xwayland~1.19.4~1.mga6", rls:"MAGEIA6"))) {
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
