# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856337");
  script_version("2024-10-22T05:05:39+0000");
  script_cve_id("CVE-2023-52168", "CVE-2023-52169");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-10-22 05:05:39 +0000 (Tue, 22 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-07-31 04:00:31 +0000 (Wed, 31 Jul 2024)");
  script_name("openSUSE: Security Advisory for p7zip (SUSE-SU-2024:2625-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.6|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2625-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/TENNNPKTDO7AH34THZIQVFPNXN2W4DBI");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'p7zip'
  package(s) announced via the SUSE-SU-2024:2625-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for p7zip fixes the following issues:

  * CVE-2023-52168: Fixed heap-based buffer overflow in the NTFS handler allows
      two bytes to be overwritten at multiple offsets (bsc#1227358)

  * CVE-2023-52169: Fixed out-of-bounds read in NTFS handler (bsc#1227359)");

  script_tag(name:"affected", value:"'p7zip' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"p7zip-full", rpm:"p7zip-full~16.02~150200.14.12.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p7zip-debugsource", rpm:"p7zip-debugsource~16.02~150200.14.12.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p7zip", rpm:"p7zip~16.02~150200.14.12.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p7zip-full-debuginfo", rpm:"p7zip-full-debuginfo~16.02~150200.14.12.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p7zip-doc", rpm:"p7zip-doc~16.02~150200.14.12.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"p7zip-full", rpm:"p7zip-full~16.02~150200.14.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p7zip-debugsource", rpm:"p7zip-debugsource~16.02~150200.14.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p7zip", rpm:"p7zip~16.02~150200.14.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p7zip-full-debuginfo", rpm:"p7zip-full-debuginfo~16.02~150200.14.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p7zip-doc", rpm:"p7zip-doc~16.02~150200.14.12.1", rls:"openSUSELeap15.5"))) {
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
