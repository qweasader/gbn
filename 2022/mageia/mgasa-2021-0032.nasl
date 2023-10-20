# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0032");
  script_cve_id("CVE-2018-1063");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-12 01:29:00 +0000 (Thu, 12 Apr 2018)");

  script_name("Mageia: Security Advisory (MGASA-2021-0032)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0032");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0032.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22890");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2018:0913");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'policycoreutils' package(s) announced via the MGASA-2021-0032 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Context relabeling of filesystems is vulnerable to symbolic link attack,
allowing a local, unprivileged malicious entity to change the SELinux context
of an arbitrary file to a context with few restrictions. This only happens when
the relabeling process is done, usually when taking SELinux state from disabled
to enable (permissive or enforcing) (CVE-2018-1063).");

  script_tag(name:"affected", value:"'policycoreutils' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"lib64policycoreutils-devel", rpm:"lib64policycoreutils-devel~2.5~14.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolicycoreutils-devel", rpm:"libpolicycoreutils-devel~2.5~14.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"policycoreutils", rpm:"policycoreutils~2.5~14.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"policycoreutils-gui", rpm:"policycoreutils-gui~2.5~14.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"policycoreutils-newrole", rpm:"policycoreutils-newrole~2.5~14.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"policycoreutils-python", rpm:"policycoreutils-python~2.5~14.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"policycoreutils-python-utils", rpm:"policycoreutils-python-utils~2.5~14.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"policycoreutils-python3", rpm:"policycoreutils-python3~2.5~14.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"policycoreutils-restorecond", rpm:"policycoreutils-restorecond~2.5~14.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"policycoreutils-sandbox", rpm:"policycoreutils-sandbox~2.5~14.1.mga7", rls:"MAGEIA7"))) {
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
