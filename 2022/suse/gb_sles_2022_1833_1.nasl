# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1833.1");
  script_cve_id("CVE-2017-16932", "CVE-2022-29824");
  script_tag(name:"creation_date", value:"2022-05-25 04:27:55 +0000 (Wed, 25 May 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-06 15:57:06 +0000 (Wed, 06 Dec 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1833-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1833-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221833-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2' package(s) announced via the SUSE-SU-2022:1833-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libxml2 fixes the following issues:

CVE-2022-29824: Fixed integer overflow leading to out-of-bounds write in
 buf.c and tree.c (bsc#1199132).

CVE-2017-16932: Prevent infinite recursion in parameter entities
 (bsc#1069689).");

  script_tag(name:"affected", value:"'libxml2' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 8, SUSE OpenStack Cloud Crowbar 9.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2", rpm:"libxml2-2~2.9.4~46.54.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-32bit", rpm:"libxml2-2-32bit~2.9.4~46.54.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-debuginfo", rpm:"libxml2-2-debuginfo~2.9.4~46.54.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-debuginfo-32bit", rpm:"libxml2-2-debuginfo-32bit~2.9.4~46.54.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-debugsource", rpm:"libxml2-debugsource~2.9.4~46.54.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-doc", rpm:"libxml2-doc~2.9.4~46.54.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-tools", rpm:"libxml2-tools~2.9.4~46.54.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-tools-debuginfo", rpm:"libxml2-tools-debuginfo~2.9.4~46.54.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libxml2", rpm:"python-libxml2~2.9.4~46.54.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libxml2-debuginfo", rpm:"python-libxml2-debuginfo~2.9.4~46.54.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libxml2-debugsource", rpm:"python-libxml2-debugsource~2.9.4~46.54.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2", rpm:"libxml2-2~2.9.4~46.54.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-32bit", rpm:"libxml2-2-32bit~2.9.4~46.54.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-debuginfo", rpm:"libxml2-2-debuginfo~2.9.4~46.54.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-debuginfo-32bit", rpm:"libxml2-2-debuginfo-32bit~2.9.4~46.54.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-debugsource", rpm:"libxml2-debugsource~2.9.4~46.54.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-doc", rpm:"libxml2-doc~2.9.4~46.54.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-tools", rpm:"libxml2-tools~2.9.4~46.54.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-tools-debuginfo", rpm:"libxml2-tools-debuginfo~2.9.4~46.54.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libxml2", rpm:"python-libxml2~2.9.4~46.54.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libxml2-debuginfo", rpm:"python-libxml2-debuginfo~2.9.4~46.54.3", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libxml2-debugsource", rpm:"python-libxml2-debugsource~2.9.4~46.54.3", rls:"SLES12.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2", rpm:"libxml2-2~2.9.4~46.54.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-32bit", rpm:"libxml2-2-32bit~2.9.4~46.54.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-debuginfo", rpm:"libxml2-2-debuginfo~2.9.4~46.54.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-debuginfo-32bit", rpm:"libxml2-2-debuginfo-32bit~2.9.4~46.54.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-debugsource", rpm:"libxml2-debugsource~2.9.4~46.54.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-doc", rpm:"libxml2-doc~2.9.4~46.54.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-tools", rpm:"libxml2-tools~2.9.4~46.54.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-tools-debuginfo", rpm:"libxml2-tools-debuginfo~2.9.4~46.54.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libxml2", rpm:"python-libxml2~2.9.4~46.54.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libxml2-debuginfo", rpm:"python-libxml2-debuginfo~2.9.4~46.54.3", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libxml2-debugsource", rpm:"python-libxml2-debugsource~2.9.4~46.54.3", rls:"SLES12.0SP4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2", rpm:"libxml2-2~2.9.4~46.54.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-32bit", rpm:"libxml2-2-32bit~2.9.4~46.54.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-debuginfo", rpm:"libxml2-2-debuginfo~2.9.4~46.54.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-debuginfo-32bit", rpm:"libxml2-2-debuginfo-32bit~2.9.4~46.54.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-debugsource", rpm:"libxml2-debugsource~2.9.4~46.54.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-doc", rpm:"libxml2-doc~2.9.4~46.54.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-tools", rpm:"libxml2-tools~2.9.4~46.54.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-tools-debuginfo", rpm:"libxml2-tools-debuginfo~2.9.4~46.54.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libxml2", rpm:"python-libxml2~2.9.4~46.54.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libxml2-debuginfo", rpm:"python-libxml2-debuginfo~2.9.4~46.54.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libxml2-debugsource", rpm:"python-libxml2-debugsource~2.9.4~46.54.3", rls:"SLES12.0SP5"))) {
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
