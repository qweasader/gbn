# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833304");
  script_version("2024-05-16T05:05:35+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-44487");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-13 19:32:37 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 08:02:34 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for nodejs10 (SUSE-SU-2023:4295-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4295-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/M25SK77IYHTJPPNY6FCZPMTRY5NWRXRP");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs10'
  package(s) announced via the SUSE-SU-2023:4295-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs10 fixes the following issues:

  * CVE-2023-44487: Fixed the Rapid Reset attack in nghttp2. (bsc#1216190)

  ##");

  script_tag(name:"affected", value:"'nodejs10' package(s) on openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"npm10", rpm:"npm10~10.24.1~150000.1.62.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-debuginfo", rpm:"nodejs10-debuginfo~10.24.1~150000.1.62.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-debugsource", rpm:"nodejs10-debugsource~10.24.1~150000.1.62.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-devel", rpm:"nodejs10-devel~10.24.1~150000.1.62.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10", rpm:"nodejs10~10.24.1~150000.1.62.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-docs", rpm:"nodejs10-docs~10.24.1~150000.1.62.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm10", rpm:"npm10~10.24.1~150000.1.62.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-debuginfo", rpm:"nodejs10-debuginfo~10.24.1~150000.1.62.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-debugsource", rpm:"nodejs10-debugsource~10.24.1~150000.1.62.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-devel", rpm:"nodejs10-devel~10.24.1~150000.1.62.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10", rpm:"nodejs10~10.24.1~150000.1.62.3", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs10-docs", rpm:"nodejs10-docs~10.24.1~150000.1.62.3", rls:"openSUSELeap15.4"))) {
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
