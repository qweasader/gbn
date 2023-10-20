# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1830.1");
  script_cve_id("CVE-2019-13012");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1830-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1830-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191830-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glib2' package(s) announced via the SUSE-SU-2019:1830-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for glib2 fixes the following issues:

Security issue fixed:
CVE-2019-13012: Fixed improper restriction of file permissions when
 creating directories (bsc#1139959).

Non-security issue fixed:
Added explicit requires between libglib2 and libgio2 (bsc#1140122).");

  script_tag(name:"affected", value:"'glib2' package(s) on SUSE CaaS Platform 3.0, SUSE Enterprise Storage 4, SUSE Enterprise Storage 5, SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Desktop 12-SP5, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE Linux Enterprise Workstation Extension 12-SP4, SUSE Linux Enterprise Workstation Extension 12-SP5, SUSE OpenStack Cloud 7, SUSE OpenStack Cloud 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"glib2-debugsource", rpm:"glib2-debugsource~2.48.2~12.15.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2-lang", rpm:"glib2-lang~2.48.2~12.15.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2-tools", rpm:"glib2-tools~2.48.2~12.15.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2-tools-debuginfo", rpm:"glib2-tools-debuginfo~2.48.2~12.15.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgio-2_0-0", rpm:"libgio-2_0-0~2.48.2~12.15.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgio-2_0-0-32bit", rpm:"libgio-2_0-0-32bit~2.48.2~12.15.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgio-2_0-0-debuginfo", rpm:"libgio-2_0-0-debuginfo~2.48.2~12.15.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgio-2_0-0-debuginfo-32bit", rpm:"libgio-2_0-0-debuginfo-32bit~2.48.2~12.15.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglib-2_0-0", rpm:"libglib-2_0-0~2.48.2~12.15.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglib-2_0-0-32bit", rpm:"libglib-2_0-0-32bit~2.48.2~12.15.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglib-2_0-0-debuginfo", rpm:"libglib-2_0-0-debuginfo~2.48.2~12.15.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglib-2_0-0-debuginfo-32bit", rpm:"libglib-2_0-0-debuginfo-32bit~2.48.2~12.15.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmodule-2_0-0", rpm:"libgmodule-2_0-0~2.48.2~12.15.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmodule-2_0-0-32bit", rpm:"libgmodule-2_0-0-32bit~2.48.2~12.15.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmodule-2_0-0-debuginfo", rpm:"libgmodule-2_0-0-debuginfo~2.48.2~12.15.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmodule-2_0-0-debuginfo-32bit", rpm:"libgmodule-2_0-0-debuginfo-32bit~2.48.2~12.15.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgobject-2_0-0", rpm:"libgobject-2_0-0~2.48.2~12.15.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgobject-2_0-0-32bit", rpm:"libgobject-2_0-0-32bit~2.48.2~12.15.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgobject-2_0-0-debuginfo", rpm:"libgobject-2_0-0-debuginfo~2.48.2~12.15.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgobject-2_0-0-debuginfo-32bit", rpm:"libgobject-2_0-0-debuginfo-32bit~2.48.2~12.15.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgthread-2_0-0", rpm:"libgthread-2_0-0~2.48.2~12.15.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgthread-2_0-0-32bit", rpm:"libgthread-2_0-0-32bit~2.48.2~12.15.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgthread-2_0-0-debuginfo", rpm:"libgthread-2_0-0-debuginfo~2.48.2~12.15.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgthread-2_0-0-debuginfo-32bit", rpm:"libgthread-2_0-0-debuginfo-32bit~2.48.2~12.15.1", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"glib2-debugsource", rpm:"glib2-debugsource~2.48.2~12.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2-lang", rpm:"glib2-lang~2.48.2~12.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2-tools", rpm:"glib2-tools~2.48.2~12.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2-tools-debuginfo", rpm:"glib2-tools-debuginfo~2.48.2~12.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgio-2_0-0", rpm:"libgio-2_0-0~2.48.2~12.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgio-2_0-0-32bit", rpm:"libgio-2_0-0-32bit~2.48.2~12.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgio-2_0-0-debuginfo", rpm:"libgio-2_0-0-debuginfo~2.48.2~12.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgio-2_0-0-debuginfo-32bit", rpm:"libgio-2_0-0-debuginfo-32bit~2.48.2~12.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglib-2_0-0", rpm:"libglib-2_0-0~2.48.2~12.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglib-2_0-0-32bit", rpm:"libglib-2_0-0-32bit~2.48.2~12.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglib-2_0-0-debuginfo", rpm:"libglib-2_0-0-debuginfo~2.48.2~12.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglib-2_0-0-debuginfo-32bit", rpm:"libglib-2_0-0-debuginfo-32bit~2.48.2~12.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmodule-2_0-0", rpm:"libgmodule-2_0-0~2.48.2~12.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmodule-2_0-0-32bit", rpm:"libgmodule-2_0-0-32bit~2.48.2~12.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmodule-2_0-0-debuginfo", rpm:"libgmodule-2_0-0-debuginfo~2.48.2~12.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmodule-2_0-0-debuginfo-32bit", rpm:"libgmodule-2_0-0-debuginfo-32bit~2.48.2~12.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgobject-2_0-0", rpm:"libgobject-2_0-0~2.48.2~12.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgobject-2_0-0-32bit", rpm:"libgobject-2_0-0-32bit~2.48.2~12.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgobject-2_0-0-debuginfo", rpm:"libgobject-2_0-0-debuginfo~2.48.2~12.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgobject-2_0-0-debuginfo-32bit", rpm:"libgobject-2_0-0-debuginfo-32bit~2.48.2~12.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgthread-2_0-0", rpm:"libgthread-2_0-0~2.48.2~12.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgthread-2_0-0-32bit", rpm:"libgthread-2_0-0-32bit~2.48.2~12.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgthread-2_0-0-debuginfo", rpm:"libgthread-2_0-0-debuginfo~2.48.2~12.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgthread-2_0-0-debuginfo-32bit", rpm:"libgthread-2_0-0-debuginfo-32bit~2.48.2~12.15.1", rls:"SLES12.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"glib2-debugsource", rpm:"glib2-debugsource~2.48.2~12.15.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2-lang", rpm:"glib2-lang~2.48.2~12.15.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2-tools", rpm:"glib2-tools~2.48.2~12.15.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2-tools-debuginfo", rpm:"glib2-tools-debuginfo~2.48.2~12.15.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgio-2_0-0", rpm:"libgio-2_0-0~2.48.2~12.15.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgio-2_0-0-32bit", rpm:"libgio-2_0-0-32bit~2.48.2~12.15.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgio-2_0-0-debuginfo", rpm:"libgio-2_0-0-debuginfo~2.48.2~12.15.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgio-2_0-0-debuginfo-32bit", rpm:"libgio-2_0-0-debuginfo-32bit~2.48.2~12.15.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglib-2_0-0", rpm:"libglib-2_0-0~2.48.2~12.15.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglib-2_0-0-32bit", rpm:"libglib-2_0-0-32bit~2.48.2~12.15.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglib-2_0-0-debuginfo", rpm:"libglib-2_0-0-debuginfo~2.48.2~12.15.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglib-2_0-0-debuginfo-32bit", rpm:"libglib-2_0-0-debuginfo-32bit~2.48.2~12.15.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmodule-2_0-0", rpm:"libgmodule-2_0-0~2.48.2~12.15.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmodule-2_0-0-32bit", rpm:"libgmodule-2_0-0-32bit~2.48.2~12.15.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmodule-2_0-0-debuginfo", rpm:"libgmodule-2_0-0-debuginfo~2.48.2~12.15.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmodule-2_0-0-debuginfo-32bit", rpm:"libgmodule-2_0-0-debuginfo-32bit~2.48.2~12.15.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgobject-2_0-0", rpm:"libgobject-2_0-0~2.48.2~12.15.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgobject-2_0-0-32bit", rpm:"libgobject-2_0-0-32bit~2.48.2~12.15.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgobject-2_0-0-debuginfo", rpm:"libgobject-2_0-0-debuginfo~2.48.2~12.15.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgobject-2_0-0-debuginfo-32bit", rpm:"libgobject-2_0-0-debuginfo-32bit~2.48.2~12.15.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgthread-2_0-0", rpm:"libgthread-2_0-0~2.48.2~12.15.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgthread-2_0-0-32bit", rpm:"libgthread-2_0-0-32bit~2.48.2~12.15.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgthread-2_0-0-debuginfo", rpm:"libgthread-2_0-0-debuginfo~2.48.2~12.15.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgthread-2_0-0-debuginfo-32bit", rpm:"libgthread-2_0-0-debuginfo-32bit~2.48.2~12.15.1", rls:"SLES12.0SP4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"glib2-debugsource", rpm:"glib2-debugsource~2.48.2~12.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2-lang", rpm:"glib2-lang~2.48.2~12.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2-tools", rpm:"glib2-tools~2.48.2~12.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glib2-tools-debuginfo", rpm:"glib2-tools-debuginfo~2.48.2~12.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgio-2_0-0", rpm:"libgio-2_0-0~2.48.2~12.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgio-2_0-0-32bit", rpm:"libgio-2_0-0-32bit~2.48.2~12.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgio-2_0-0-debuginfo", rpm:"libgio-2_0-0-debuginfo~2.48.2~12.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgio-2_0-0-debuginfo-32bit", rpm:"libgio-2_0-0-debuginfo-32bit~2.48.2~12.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglib-2_0-0", rpm:"libglib-2_0-0~2.48.2~12.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglib-2_0-0-32bit", rpm:"libglib-2_0-0-32bit~2.48.2~12.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglib-2_0-0-debuginfo", rpm:"libglib-2_0-0-debuginfo~2.48.2~12.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglib-2_0-0-debuginfo-32bit", rpm:"libglib-2_0-0-debuginfo-32bit~2.48.2~12.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmodule-2_0-0", rpm:"libgmodule-2_0-0~2.48.2~12.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmodule-2_0-0-32bit", rpm:"libgmodule-2_0-0-32bit~2.48.2~12.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmodule-2_0-0-debuginfo", rpm:"libgmodule-2_0-0-debuginfo~2.48.2~12.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgmodule-2_0-0-debuginfo-32bit", rpm:"libgmodule-2_0-0-debuginfo-32bit~2.48.2~12.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgobject-2_0-0", rpm:"libgobject-2_0-0~2.48.2~12.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgobject-2_0-0-32bit", rpm:"libgobject-2_0-0-32bit~2.48.2~12.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgobject-2_0-0-debuginfo", rpm:"libgobject-2_0-0-debuginfo~2.48.2~12.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgobject-2_0-0-debuginfo-32bit", rpm:"libgobject-2_0-0-debuginfo-32bit~2.48.2~12.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgthread-2_0-0", rpm:"libgthread-2_0-0~2.48.2~12.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgthread-2_0-0-32bit", rpm:"libgthread-2_0-0-32bit~2.48.2~12.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgthread-2_0-0-debuginfo", rpm:"libgthread-2_0-0-debuginfo~2.48.2~12.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgthread-2_0-0-debuginfo-32bit", rpm:"libgthread-2_0-0-debuginfo-32bit~2.48.2~12.15.1", rls:"SLES12.0SP5"))) {
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
