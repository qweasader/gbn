# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833105");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2023-40359");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-22 18:53:55 +0000 (Tue, 22 Aug 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:11:27 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for xterm (SUSE-SU-2023:4438-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4438-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QKJ4NTM23PVYYOU5FSY7S2X3NHWP5PID");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xterm'
  package(s) announced via the SUSE-SU-2023:4438-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xterm fixes the following issues:

  * CVE-2023-40359: Fixed reporting characterset names in ReGiS graphics mode.
      (bsc#1214282)

  ##");

  script_tag(name:"affected", value:"'xterm' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"xterm-bin-330", rpm:"xterm-bin-330~150200.11.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xterm-debugsource-330", rpm:"xterm-debugsource-330~150200.11.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xterm-bin-debuginfo-330", rpm:"xterm-bin-debuginfo-330~150200.11.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xterm-330", rpm:"xterm-330~150200.11.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xterm-bin-330", rpm:"xterm-bin-330~150200.11.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xterm-debugsource-330", rpm:"xterm-debugsource-330~150200.11.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xterm-bin-debuginfo-330", rpm:"xterm-bin-debuginfo-330~150200.11.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xterm-330", rpm:"xterm-330~150200.11.12.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"xterm-bin-330", rpm:"xterm-bin-330~150200.11.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xterm-debugsource-330", rpm:"xterm-debugsource-330~150200.11.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xterm-bin-debuginfo-330", rpm:"xterm-bin-debuginfo-330~150200.11.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xterm-330", rpm:"xterm-330~150200.11.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xterm-bin-330", rpm:"xterm-bin-330~150200.11.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xterm-debugsource-330", rpm:"xterm-debugsource-330~150200.11.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xterm-bin-debuginfo-330", rpm:"xterm-bin-debuginfo-330~150200.11.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xterm-330", rpm:"xterm-330~150200.11.12.1", rls:"openSUSELeap15.5"))) {
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