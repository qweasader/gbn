# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833327");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2024-0408", "CVE-2024-0409");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-30 23:03:34 +0000 (Tue, 30 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-03-04 12:55:56 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for xwayland (SUSE-SU-2024:0212-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0212-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/MK72ETIY6O7KQLJWS6BN7OQR6ZKUATOS");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xwayland'
  package(s) announced via the SUSE-SU-2024:0212-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xwayland fixes the following issues:

  * CVE-2024-0408: Fixed SELinux unlabeled GLX PBuffer. (bsc#1218845)

  * CVE-2024-0409: Fixed SELinux context corruption. (bsc#1218846)

  ##");

  script_tag(name:"affected", value:"'xwayland' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"xwayland-devel", rpm:"xwayland-devel~22.1.5~150500.7.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xwayland", rpm:"xwayland~22.1.5~150500.7.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xwayland-debuginfo", rpm:"xwayland-debuginfo~22.1.5~150500.7.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xwayland-debugsource", rpm:"xwayland-debugsource~22.1.5~150500.7.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xwayland-devel", rpm:"xwayland-devel~22.1.5~150500.7.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xwayland", rpm:"xwayland~22.1.5~150500.7.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xwayland-debuginfo", rpm:"xwayland-debuginfo~22.1.5~150500.7.17.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xwayland-debugsource", rpm:"xwayland-debugsource~22.1.5~150500.7.17.1", rls:"openSUSELeap15.5"))) {
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