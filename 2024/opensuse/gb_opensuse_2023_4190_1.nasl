# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833802");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2023-3817", "CVE-2023-5363");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-09 13:55:32 +0000 (Thu, 09 Nov 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:23:54 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for openssl (SUSE-SU-2023:4190-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4190-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6Z2A44WZBLOE2C56CN35SLEQHNX67JAK");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl'
  package(s) announced via the SUSE-SU-2023:4190-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssl-3 fixes the following issues:

  * CVE-2023-5363: Incorrect cipher key and IV length processing. (bsc#1216163)

  * CVE-2023-3817: Add test of DH_check() with q = p + 1. (bsc#1213853)

  ##");

  script_tag(name:"affected", value:"'openssl' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"libopenssl3", rpm:"libopenssl3~3.0.8~150500.5.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-3-debugsource", rpm:"openssl-3-debugsource~3.0.8~150500.5.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-3-debuginfo", rpm:"openssl-3-debuginfo~3.0.8~150500.5.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-3", rpm:"openssl-3~3.0.8~150500.5.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-3-devel", rpm:"libopenssl-3-devel~3.0.8~150500.5.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl3-debuginfo", rpm:"libopenssl3-debuginfo~3.0.8~150500.5.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl3-32bit", rpm:"libopenssl3-32bit~3.0.8~150500.5.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-3-devel-32bit", rpm:"libopenssl-3-devel-32bit~3.0.8~150500.5.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl3-32bit-debuginfo", rpm:"libopenssl3-32bit-debuginfo~3.0.8~150500.5.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-3-doc", rpm:"openssl-3-doc~3.0.8~150500.5.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl3-64bit-debuginfo", rpm:"libopenssl3-64bit-debuginfo~3.0.8~150500.5.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-3-devel-64bit", rpm:"libopenssl-3-devel-64bit~3.0.8~150500.5.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl3-64bit", rpm:"libopenssl3-64bit~3.0.8~150500.5.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl3", rpm:"libopenssl3~3.0.8~150500.5.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-3-debugsource", rpm:"openssl-3-debugsource~3.0.8~150500.5.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-3-debuginfo", rpm:"openssl-3-debuginfo~3.0.8~150500.5.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-3", rpm:"openssl-3~3.0.8~150500.5.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-3-devel", rpm:"libopenssl-3-devel~3.0.8~150500.5.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl3-debuginfo", rpm:"libopenssl3-debuginfo~3.0.8~150500.5.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl3-32bit", rpm:"libopenssl3-32bit~3.0.8~150500.5.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-3-devel-32bit", rpm:"libopenssl-3-devel-32bit~3.0.8~150500.5.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl3-32bit-debuginfo", rpm:"libopenssl3-32bit-debuginfo~3.0.8~150500.5.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-3-doc", rpm:"openssl-3-doc~3.0.8~150500.5.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl3-64bit-debuginfo", rpm:"libopenssl3-64bit-debuginfo~3.0.8~150500.5.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-3-devel-64bit", rpm:"libopenssl-3-devel-64bit~3.0.8~150500.5.14.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl3-64bit", rpm:"libopenssl3-64bit~3.0.8~150500.5.14.1", rls:"openSUSELeap15.5"))) {
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