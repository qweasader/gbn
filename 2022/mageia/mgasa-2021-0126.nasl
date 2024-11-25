# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0126");
  script_cve_id("CVE-2020-25678", "CVE-2020-27839");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-01T14:37:13+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:13 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-03 18:37:47 +0000 (Thu, 03 Jun 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0126)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0126");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0126.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28538");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/OQTBKVXVYP7GPQNZ5VASOIJHMLK7727M/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ceph' package(s) announced via the MGASA-2021-0126 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in Ceph where Ceph stores mgr module passwords in clear text.
This issue can be found by searching the mgr logs for Grafana and dashboard
with passwords visible. The highest threat from this vulnerability is to
confidentiality (CVE-2020-25678).

A flaw was found in ceph-dashboard. The JSON Web Token (JWT) used for user
authentication is stored by the frontend application in the browser's
localStorage which is potentially vulnerable to attackers via XSS attacks. The
highest threat from this vulnerability is to data confidentiality and
integrity (CVE-2020-27839).");

  script_tag(name:"affected", value:"'ceph' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"ceph", rpm:"ceph~15.2.9~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-fuse", rpm:"ceph-fuse~15.2.9~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-immutable-object-cache", rpm:"ceph-immutable-object-cache~15.2.9~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-mds", rpm:"ceph-mds~15.2.9~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-mgr", rpm:"ceph-mgr~15.2.9~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-mon", rpm:"ceph-mon~15.2.9~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-osd", rpm:"ceph-osd~15.2.9~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-radosgw", rpm:"ceph-radosgw~15.2.9~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-rbd", rpm:"ceph-rbd~15.2.9~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ceph-devel", rpm:"lib64ceph-devel~15.2.9~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ceph2", rpm:"lib64ceph2~15.2.9~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64rados-devel", rpm:"lib64rados-devel~15.2.9~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64rados2", rpm:"lib64rados2~15.2.9~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64radosgw-devel", rpm:"lib64radosgw-devel~15.2.9~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64radosgw2", rpm:"lib64radosgw2~15.2.9~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64radosstriper-devel", rpm:"lib64radosstriper-devel~15.2.9~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64radosstriper1", rpm:"lib64radosstriper1~15.2.9~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64rbd-devel", rpm:"lib64rbd-devel~15.2.9~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64rbd1", rpm:"lib64rbd1~15.2.9~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64rgw-devel", rpm:"lib64rgw-devel~15.2.9~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64rgw2", rpm:"lib64rgw2~15.2.9~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ceph", rpm:"python3-ceph~15.2.9~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rados", rpm:"python3-rados~15.2.9~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rbd", rpm:"python3-rbd~15.2.9~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rgw", rpm:"python3-rgw~15.2.9~1.mga8", rls:"MAGEIA8"))) {
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
