# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856358");
  script_version("2024-08-23T05:05:37+0000");
  script_cve_id("CVE-2023-52890");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-08-23 05:05:37 +0000 (Fri, 23 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-08-20 04:00:55 +0000 (Tue, 20 Aug 2024)");
  script_name("openSUSE: Security Advisory for ntfs (SUSE-SU-2024:2187-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.6|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2187-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/M2T36ITNEMHD5DLL56EBYL7O4ORVVRLQ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntfs'
  package(s) announced via the SUSE-SU-2024:2187-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ntfs-3g_ntfsprogs fixes the following issue:

  * CVE-2023-52890: fix a use after free in ntfs_uppercase_mbs (bsc#1226007)

  ##");

  script_tag(name:"affected", value:"'ntfs' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libntfs-3g87-debuginfo", rpm:"libntfs-3g87-debuginfo~2022.5.17~150000.3.21.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfs-3g", rpm:"ntfs-3g~2022.5.17~150000.3.21.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfsprogs", rpm:"ntfsprogs~2022.5.17~150000.3.21.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfsprogs-extra", rpm:"ntfsprogs-extra~2022.5.17~150000.3.21.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfs-3g_ntfsprogs-debuginfo", rpm:"ntfs-3g_ntfsprogs-debuginfo~2022.5.17~150000.3.21.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfs-3g-debuginfo", rpm:"ntfs-3g-debuginfo~2022.5.17~150000.3.21.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libntfs-3g-devel", rpm:"libntfs-3g-devel~2022.5.17~150000.3.21.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libntfs-3g87", rpm:"libntfs-3g87~2022.5.17~150000.3.21.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfsprogs-extra-debuginfo", rpm:"ntfsprogs-extra-debuginfo~2022.5.17~150000.3.21.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfs-3g_ntfsprogs-debugsource", rpm:"ntfs-3g_ntfsprogs-debugsource~2022.5.17~150000.3.21.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfsprogs-debuginfo", rpm:"ntfsprogs-debuginfo~2022.5.17~150000.3.21.1", rls:"openSUSELeap15.6"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libntfs-3g87-debuginfo", rpm:"libntfs-3g87-debuginfo~2022.5.17~150000.3.21.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfs-3g", rpm:"ntfs-3g~2022.5.17~150000.3.21.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfsprogs", rpm:"ntfsprogs~2022.5.17~150000.3.21.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfsprogs-extra", rpm:"ntfsprogs-extra~2022.5.17~150000.3.21.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfs-3g_ntfsprogs-debuginfo", rpm:"ntfs-3g_ntfsprogs-debuginfo~2022.5.17~150000.3.21.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfs-3g-debuginfo", rpm:"ntfs-3g-debuginfo~2022.5.17~150000.3.21.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libntfs-3g-devel", rpm:"libntfs-3g-devel~2022.5.17~150000.3.21.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libntfs-3g87", rpm:"libntfs-3g87~2022.5.17~150000.3.21.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfsprogs-extra-debuginfo", rpm:"ntfsprogs-extra-debuginfo~2022.5.17~150000.3.21.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfs-3g_ntfsprogs-debugsource", rpm:"ntfs-3g_ntfsprogs-debugsource~2022.5.17~150000.3.21.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntfsprogs-debuginfo", rpm:"ntfsprogs-debuginfo~2022.5.17~150000.3.21.1", rls:"openSUSELeap15.5"))) {
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