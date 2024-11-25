# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.1408.1");
  script_cve_id("CVE-2021-25900");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:39 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-02 19:56:31 +0000 (Tue, 02 Feb 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:1408-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:1408-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20211408-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'librsvg' package(s) announced via the SUSE-SU-2021:1408-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for librsvg fixes the following issues:

librsvg was updated to 2.46.5:
 * Update dependent crates that had security vulnerabilities: smallvec to
 0.6.14 - RUSTSEC-2018-0003 - CVE-2021-25900 (bsc#1183403)");

  script_tag(name:"affected", value:"'librsvg' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Desktop Applications 15-SP2, SUSE Linux Enterprise Module for Desktop Applications 15-SP3.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-loader-rsvg", rpm:"gdk-pixbuf-loader-rsvg~2.46.5~3.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-loader-rsvg-debuginfo", rpm:"gdk-pixbuf-loader-rsvg-debuginfo~2.46.5~3.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librsvg-2-2", rpm:"librsvg-2-2~2.46.5~3.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librsvg-2-2-debuginfo", rpm:"librsvg-2-2-debuginfo~2.46.5~3.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librsvg-debugsource", rpm:"librsvg-debugsource~2.46.5~3.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librsvg-devel", rpm:"librsvg-devel~2.46.5~3.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Rsvg-2_0", rpm:"typelib-1_0-Rsvg-2_0~2.46.5~3.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-loader-rsvg", rpm:"gdk-pixbuf-loader-rsvg~2.46.5~3.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-loader-rsvg-debuginfo", rpm:"gdk-pixbuf-loader-rsvg-debuginfo~2.46.5~3.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librsvg-2-2", rpm:"librsvg-2-2~2.46.5~3.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librsvg-2-2-debuginfo", rpm:"librsvg-2-2-debuginfo~2.46.5~3.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librsvg-debugsource", rpm:"librsvg-debugsource~2.46.5~3.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"librsvg-devel", rpm:"librsvg-devel~2.46.5~3.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Rsvg-2_0", rpm:"typelib-1_0-Rsvg-2_0~2.46.5~3.3.1", rls:"SLES15.0SP3"))) {
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
