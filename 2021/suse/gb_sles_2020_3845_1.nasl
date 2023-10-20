# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3845.1");
  script_cve_id("CVE-2020-16121");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:47 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-18 14:30:00 +0000 (Wed, 18 Nov 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3845-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3845-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203845-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'PackageKit' package(s) announced via the SUSE-SU-2020:3845-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for PackageKit fixes the following issue:

CVE-2020-16121: Fixed an Information disclosure in InstallFiles,
 GetFilesLocal and GetDetailsLocal (bsc#1176930).

Notify service manager when it shutdown and cleanup temporary files when
 PackageKit quits. (bsc#1169739)");

  script_tag(name:"affected", value:"'PackageKit' package(s) on SUSE Linux Enterprise Module for Desktop Applications 15-SP1, SUSE Linux Enterprise Workstation Extension 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"PackageKit", rpm:"PackageKit~1.1.10~12.10.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"PackageKit-backend-zypp", rpm:"PackageKit-backend-zypp~1.1.10~12.10.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"PackageKit-backend-zypp-debuginfo", rpm:"PackageKit-backend-zypp-debuginfo~1.1.10~12.10.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"PackageKit-debuginfo", rpm:"PackageKit-debuginfo~1.1.10~12.10.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"PackageKit-debugsource", rpm:"PackageKit-debugsource~1.1.10~12.10.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"PackageKit-devel", rpm:"PackageKit-devel~1.1.10~12.10.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"PackageKit-devel-debuginfo", rpm:"PackageKit-devel-debuginfo~1.1.10~12.10.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"PackageKit-lang", rpm:"PackageKit-lang~1.1.10~12.10.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpackagekit-glib2-18", rpm:"libpackagekit-glib2-18~1.1.10~12.10.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpackagekit-glib2-18-debuginfo", rpm:"libpackagekit-glib2-18-debuginfo~1.1.10~12.10.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpackagekit-glib2-devel", rpm:"libpackagekit-glib2-devel~1.1.10~12.10.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-PackageKitGlib-1_0", rpm:"typelib-1_0-PackageKitGlib-1_0~1.1.10~12.10.1", rls:"SLES15.0SP1"))) {
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
