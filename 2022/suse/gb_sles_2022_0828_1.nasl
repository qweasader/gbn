# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.0828.1");
  script_cve_id("CVE-2021-3800");
  script_tag(name:"creation_date", value:"2022-03-15 04:11:51 +0000 (Tue, 15 Mar 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-10 15:39:02 +0000 (Mon, 10 Apr 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:0828-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:0828-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20220828-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glib2' package(s) announced via the SUSE-SU-2022:0828-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for glib2 fixes the following issues:

CVE-2021-3800: Fixed a file content leak in pkexec due to charset
 aliases (bsc#1191489).");

  script_tag(name:"affected", value:"'glib2' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE Linux Enterprise Workstation Extension 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"glib2-debugsource", rpm:"glib2-debugsource~2.48.2~12.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2-lang", rpm:"glib2-lang~2.48.2~12.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2-tools", rpm:"glib2-tools~2.48.2~12.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2-tools-debuginfo", rpm:"glib2-tools-debuginfo~2.48.2~12.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgio-2_0-0", rpm:"libgio-2_0-0~2.48.2~12.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgio-2_0-0-32bit", rpm:"libgio-2_0-0-32bit~2.48.2~12.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgio-2_0-0-debuginfo", rpm:"libgio-2_0-0-debuginfo~2.48.2~12.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgio-2_0-0-debuginfo-32bit", rpm:"libgio-2_0-0-debuginfo-32bit~2.48.2~12.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglib-2_0-0", rpm:"libglib-2_0-0~2.48.2~12.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglib-2_0-0-32bit", rpm:"libglib-2_0-0-32bit~2.48.2~12.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglib-2_0-0-debuginfo", rpm:"libglib-2_0-0-debuginfo~2.48.2~12.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglib-2_0-0-debuginfo-32bit", rpm:"libglib-2_0-0-debuginfo-32bit~2.48.2~12.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmodule-2_0-0", rpm:"libgmodule-2_0-0~2.48.2~12.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmodule-2_0-0-32bit", rpm:"libgmodule-2_0-0-32bit~2.48.2~12.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmodule-2_0-0-debuginfo", rpm:"libgmodule-2_0-0-debuginfo~2.48.2~12.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmodule-2_0-0-debuginfo-32bit", rpm:"libgmodule-2_0-0-debuginfo-32bit~2.48.2~12.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgobject-2_0-0", rpm:"libgobject-2_0-0~2.48.2~12.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgobject-2_0-0-32bit", rpm:"libgobject-2_0-0-32bit~2.48.2~12.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgobject-2_0-0-debuginfo", rpm:"libgobject-2_0-0-debuginfo~2.48.2~12.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgobject-2_0-0-debuginfo-32bit", rpm:"libgobject-2_0-0-debuginfo-32bit~2.48.2~12.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgthread-2_0-0", rpm:"libgthread-2_0-0~2.48.2~12.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgthread-2_0-0-32bit", rpm:"libgthread-2_0-0-32bit~2.48.2~12.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgthread-2_0-0-debuginfo", rpm:"libgthread-2_0-0-debuginfo~2.48.2~12.25.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgthread-2_0-0-debuginfo-32bit", rpm:"libgthread-2_0-0-debuginfo-32bit~2.48.2~12.25.1", rls:"SLES12.0SP5"))) {
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
