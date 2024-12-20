# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3986.1");
  script_cve_id("CVE-2022-3554", "CVE-2022-3555");
  script_tag(name:"creation_date", value:"2022-11-16 04:24:29 +0000 (Wed, 16 Nov 2022)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3986-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3986-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223986-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libX11' package(s) announced via the SUSE-SU-2022:3986-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libX11 fixes the following issues:

 - CVE-2022-3554: Fixed memory leak in XRegisterIMInstantiateCallback()
 (bsc#1204422).
 - CVE-2022-3555: Fixed memory leak in _XFreeX11XCBStructure()
 (bsc#1204425).");

  script_tag(name:"affected", value:"'libX11' package(s) on SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Micro 5.3, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Basesystem 15-SP4.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libX11-6", rpm:"libX11-6~1.6.5~150000.3.24.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6-32bit", rpm:"libX11-6-32bit~1.6.5~150000.3.24.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6-32bit-debuginfo", rpm:"libX11-6-32bit-debuginfo~1.6.5~150000.3.24.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6-debuginfo", rpm:"libX11-6-debuginfo~1.6.5~150000.3.24.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-data", rpm:"libX11-data~1.6.5~150000.3.24.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-debugsource", rpm:"libX11-debugsource~1.6.5~150000.3.24.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-devel", rpm:"libX11-devel~1.6.5~150000.3.24.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1", rpm:"libX11-xcb1~1.6.5~150000.3.24.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1-32bit", rpm:"libX11-xcb1-32bit~1.6.5~150000.3.24.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1-32bit-debuginfo", rpm:"libX11-xcb1-32bit-debuginfo~1.6.5~150000.3.24.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1-debuginfo", rpm:"libX11-xcb1-debuginfo~1.6.5~150000.3.24.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libX11-6", rpm:"libX11-6~1.6.5~150000.3.24.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6-32bit", rpm:"libX11-6-32bit~1.6.5~150000.3.24.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6-32bit-debuginfo", rpm:"libX11-6-32bit-debuginfo~1.6.5~150000.3.24.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6-debuginfo", rpm:"libX11-6-debuginfo~1.6.5~150000.3.24.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-data", rpm:"libX11-data~1.6.5~150000.3.24.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-debugsource", rpm:"libX11-debugsource~1.6.5~150000.3.24.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-devel", rpm:"libX11-devel~1.6.5~150000.3.24.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1", rpm:"libX11-xcb1~1.6.5~150000.3.24.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1-32bit", rpm:"libX11-xcb1-32bit~1.6.5~150000.3.24.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1-32bit-debuginfo", rpm:"libX11-xcb1-32bit-debuginfo~1.6.5~150000.3.24.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1-debuginfo", rpm:"libX11-xcb1-debuginfo~1.6.5~150000.3.24.1", rls:"SLES15.0SP4"))) {
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
