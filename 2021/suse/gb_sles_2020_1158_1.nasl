# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1158.1");
  script_cve_id("CVE-2020-12059");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-24 17:15:00 +0000 (Thu, 24 Sep 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1158-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1158-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201158-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ceph' package(s) announced via the SUSE-SU-2020:1158-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ceph fixes the following issues:

CVE-2020-12059: Fixed a denial of service caused by a specially crafted
 XML payload on POST requests (bsc#1170170).");

  script_tag(name:"affected", value:"'ceph' package(s) on SUSE Enterprise Storage 5, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud Crowbar 8.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"ceph-common", rpm:"ceph-common~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-common-debuginfo", rpm:"ceph-common-debuginfo~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-debugsource", rpm:"ceph-debugsource~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcephfs2", rpm:"libcephfs2~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcephfs2-debuginfo", rpm:"libcephfs2-debuginfo~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados2", rpm:"librados2~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados2-debuginfo", rpm:"librados2-debuginfo~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libradosstriper1", rpm:"libradosstriper1~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libradosstriper1-debuginfo", rpm:"libradosstriper1-debuginfo~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librbd1", rpm:"librbd1~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librbd1-debuginfo", rpm:"librbd1-debuginfo~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librgw2", rpm:"librgw2~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librgw2-debuginfo", rpm:"librgw2-debuginfo~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-cephfs", rpm:"python-cephfs~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-cephfs-debuginfo", rpm:"python-cephfs-debuginfo~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-rados", rpm:"python-rados~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-rados-debuginfo", rpm:"python-rados-debuginfo~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-rbd", rpm:"python-rbd~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-rbd-debuginfo", rpm:"python-rbd-debuginfo~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-rgw", rpm:"python-rgw~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-rgw-debuginfo", rpm:"python-rgw-debuginfo~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"ceph-common", rpm:"ceph-common~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-common-debuginfo", rpm:"ceph-common-debuginfo~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-debugsource", rpm:"ceph-debugsource~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcephfs2", rpm:"libcephfs2~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcephfs2-debuginfo", rpm:"libcephfs2-debuginfo~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados2", rpm:"librados2~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados2-debuginfo", rpm:"librados2-debuginfo~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libradosstriper1", rpm:"libradosstriper1~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libradosstriper1-debuginfo", rpm:"libradosstriper1-debuginfo~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librbd1", rpm:"librbd1~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librbd1-debuginfo", rpm:"librbd1-debuginfo~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librgw2", rpm:"librgw2~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librgw2-debuginfo", rpm:"librgw2-debuginfo~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-cephfs", rpm:"python-cephfs~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-cephfs-debuginfo", rpm:"python-cephfs-debuginfo~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-rados", rpm:"python-rados~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-rados-debuginfo", rpm:"python-rados-debuginfo~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-rbd", rpm:"python-rbd~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-rbd-debuginfo", rpm:"python-rbd-debuginfo~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-rgw", rpm:"python-rgw~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-rgw-debuginfo", rpm:"python-rgw-debuginfo~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"ceph-common", rpm:"ceph-common~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-common-debuginfo", rpm:"ceph-common-debuginfo~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-debugsource", rpm:"ceph-debugsource~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcephfs2", rpm:"libcephfs2~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcephfs2-debuginfo", rpm:"libcephfs2-debuginfo~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados2", rpm:"librados2~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librados2-debuginfo", rpm:"librados2-debuginfo~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libradosstriper1", rpm:"libradosstriper1~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libradosstriper1-debuginfo", rpm:"libradosstriper1-debuginfo~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librbd1", rpm:"librbd1~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librbd1-debuginfo", rpm:"librbd1-debuginfo~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librgw2", rpm:"librgw2~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librgw2-debuginfo", rpm:"librgw2-debuginfo~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-cephfs", rpm:"python-cephfs~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-cephfs-debuginfo", rpm:"python-cephfs-debuginfo~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-rados", rpm:"python-rados~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-rados-debuginfo", rpm:"python-rados-debuginfo~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-rbd", rpm:"python-rbd~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-rbd-debuginfo", rpm:"python-rbd-debuginfo~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-rgw", rpm:"python-rgw~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-rgw-debuginfo", rpm:"python-rgw-debuginfo~12.2.12+git.1587570958.35d78d0243~2.45.1", rls:"SLES12.0SP5"))) {
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
