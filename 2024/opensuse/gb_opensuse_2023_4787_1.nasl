# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833071");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2023-6377", "CVE-2023-6478");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-13 07:15:30 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:12:27 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for xorg (SUSE-SU-2023:4787-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4787-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/CUYQLMWPQL4XAWUVORDJ6HPBR56N65EX");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg'
  package(s) announced via the SUSE-SU-2023:4787-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xorg-x11-server fixes the following issues:

  * CVE-2023-6377: Fixed Out-of-bounds memory write in XKB button
      actions(bsc#1217765).

  * CVE-2023-6478: Fixed Out-of-bounds memory read in RRChangeOutputProperty and
      RRChangeProviderProperty (bsc#1217766).

  ##");

  script_tag(name:"affected", value:"'xorg' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xvfb", rpm:"xorg-x11-server-Xvfb~21.1.4~150500.7.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-extra", rpm:"xorg-x11-server-extra~21.1.4~150500.7.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-extra-debuginfo", rpm:"xorg-x11-server-extra-debuginfo~21.1.4~150500.7.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xvfb-debuginfo", rpm:"xorg-x11-server-Xvfb-debuginfo~21.1.4~150500.7.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-debugsource", rpm:"xorg-x11-server-debugsource~21.1.4~150500.7.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-sdk", rpm:"xorg-x11-server-sdk~21.1.4~150500.7.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-debuginfo", rpm:"xorg-x11-server-debuginfo~21.1.4~150500.7.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-source", rpm:"xorg-x11-server-source~21.1.4~150500.7.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server", rpm:"xorg-x11-server~21.1.4~150500.7.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xvfb", rpm:"xorg-x11-server-Xvfb~21.1.4~150500.7.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-extra", rpm:"xorg-x11-server-extra~21.1.4~150500.7.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-extra-debuginfo", rpm:"xorg-x11-server-extra-debuginfo~21.1.4~150500.7.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xvfb-debuginfo", rpm:"xorg-x11-server-Xvfb-debuginfo~21.1.4~150500.7.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-debugsource", rpm:"xorg-x11-server-debugsource~21.1.4~150500.7.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-sdk", rpm:"xorg-x11-server-sdk~21.1.4~150500.7.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-debuginfo", rpm:"xorg-x11-server-debuginfo~21.1.4~150500.7.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-source", rpm:"xorg-x11-server-source~21.1.4~150500.7.10.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server", rpm:"xorg-x11-server~21.1.4~150500.7.10.1", rls:"openSUSELeap15.5"))) {
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