# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.3125.1");
  script_cve_id("CVE-2017-5884", "CVE-2017-5885");
  script_tag(name:"creation_date", value:"2021-09-23 07:04:43 +0000 (Thu, 23 Sep 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-02 15:35:51 +0000 (Thu, 02 Mar 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:3125-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:3125-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20213125-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gtk-vnc' package(s) announced via the SUSE-SU-2021:3125-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gtk-vnc fixes the following issues:

CVE-2017-5885: Correctly validate color map range indexes (bsc#1024268).

CVE-2017-5884: Fix bounds checking for RRE, hextile & copyrect encodings
 (bsc#1024266).

Fix crash when opening connection from a GSocketAddress (bsc#1046782).

Fix possible crash on connection failure (bsc#1188292).");

  script_tag(name:"affected", value:"'gtk-vnc' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE Linux Enterprise Workstation Extension 12-SP5, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 8, SUSE OpenStack Cloud Crowbar 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"gtk-vnc-debugsource", rpm:"gtk-vnc-debugsource~0.6.0~11.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk-vnc2-debugsource", rpm:"gtk-vnc2-debugsource~0.6.0~11.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-vnc-1_0-0", rpm:"libgtk-vnc-1_0-0~0.6.0~11.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-vnc-1_0-0-debuginfo", rpm:"libgtk-vnc-1_0-0-debuginfo~0.6.0~11.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-vnc-2_0-0", rpm:"libgtk-vnc-2_0-0~0.6.0~11.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-vnc-2_0-0-debuginfo", rpm:"libgtk-vnc-2_0-0-debuginfo~0.6.0~11.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgvnc-1_0-0", rpm:"libgvnc-1_0-0~0.6.0~11.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgvnc-1_0-0-debuginfo", rpm:"libgvnc-1_0-0-debuginfo~0.6.0~11.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-gtk-vnc", rpm:"python-gtk-vnc~0.6.0~11.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-gtk-vnc-debuginfo", rpm:"python-gtk-vnc-debuginfo~0.6.0~11.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GVnc-1_0", rpm:"typelib-1_0-GVnc-1_0~0.6.0~11.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GtkVnc-2_0", rpm:"typelib-1_0-GtkVnc-2_0~0.6.0~11.3.1", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"gtk-vnc-debugsource", rpm:"gtk-vnc-debugsource~0.6.0~11.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk-vnc2-debugsource", rpm:"gtk-vnc2-debugsource~0.6.0~11.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-vnc-1_0-0", rpm:"libgtk-vnc-1_0-0~0.6.0~11.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-vnc-1_0-0-debuginfo", rpm:"libgtk-vnc-1_0-0-debuginfo~0.6.0~11.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-vnc-2_0-0", rpm:"libgtk-vnc-2_0-0~0.6.0~11.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-vnc-2_0-0-debuginfo", rpm:"libgtk-vnc-2_0-0-debuginfo~0.6.0~11.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgvnc-1_0-0", rpm:"libgvnc-1_0-0~0.6.0~11.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgvnc-1_0-0-debuginfo", rpm:"libgvnc-1_0-0-debuginfo~0.6.0~11.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-gtk-vnc", rpm:"python-gtk-vnc~0.6.0~11.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-gtk-vnc-debuginfo", rpm:"python-gtk-vnc-debuginfo~0.6.0~11.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GVnc-1_0", rpm:"typelib-1_0-GVnc-1_0~0.6.0~11.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GtkVnc-2_0", rpm:"typelib-1_0-GtkVnc-2_0~0.6.0~11.3.1", rls:"SLES12.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"gtk-vnc-debugsource", rpm:"gtk-vnc-debugsource~0.6.0~11.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk-vnc2-debugsource", rpm:"gtk-vnc2-debugsource~0.6.0~11.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-vnc-1_0-0", rpm:"libgtk-vnc-1_0-0~0.6.0~11.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-vnc-1_0-0-debuginfo", rpm:"libgtk-vnc-1_0-0-debuginfo~0.6.0~11.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-vnc-2_0-0", rpm:"libgtk-vnc-2_0-0~0.6.0~11.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-vnc-2_0-0-debuginfo", rpm:"libgtk-vnc-2_0-0-debuginfo~0.6.0~11.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgvnc-1_0-0", rpm:"libgvnc-1_0-0~0.6.0~11.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgvnc-1_0-0-debuginfo", rpm:"libgvnc-1_0-0-debuginfo~0.6.0~11.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-gtk-vnc", rpm:"python-gtk-vnc~0.6.0~11.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-gtk-vnc-debuginfo", rpm:"python-gtk-vnc-debuginfo~0.6.0~11.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GVnc-1_0", rpm:"typelib-1_0-GVnc-1_0~0.6.0~11.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GtkVnc-2_0", rpm:"typelib-1_0-GtkVnc-2_0~0.6.0~11.3.1", rls:"SLES12.0SP4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"gtk-vnc-debugsource", rpm:"gtk-vnc-debugsource~0.6.0~11.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk-vnc2-debugsource", rpm:"gtk-vnc2-debugsource~0.6.0~11.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-vnc-1_0-0", rpm:"libgtk-vnc-1_0-0~0.6.0~11.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-vnc-1_0-0-debuginfo", rpm:"libgtk-vnc-1_0-0-debuginfo~0.6.0~11.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-vnc-2_0-0", rpm:"libgtk-vnc-2_0-0~0.6.0~11.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgtk-vnc-2_0-0-debuginfo", rpm:"libgtk-vnc-2_0-0-debuginfo~0.6.0~11.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgvnc-1_0-0", rpm:"libgvnc-1_0-0~0.6.0~11.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgvnc-1_0-0-debuginfo", rpm:"libgvnc-1_0-0-debuginfo~0.6.0~11.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-gtk-vnc", rpm:"python-gtk-vnc~0.6.0~11.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-gtk-vnc-debuginfo", rpm:"python-gtk-vnc-debuginfo~0.6.0~11.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GVnc-1_0", rpm:"typelib-1_0-GVnc-1_0~0.6.0~11.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GtkVnc-2_0", rpm:"typelib-1_0-GtkVnc-2_0~0.6.0~11.3.1", rls:"SLES12.0SP5"))) {
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
