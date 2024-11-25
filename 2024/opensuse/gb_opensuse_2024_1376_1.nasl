# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856102");
  script_version("2024-05-16T05:05:35+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"creation_date", value:"2024-04-25 01:00:30 +0000 (Thu, 25 Apr 2024)");
  script_name("openSUSE: Security Advisory for polkit (SUSE-SU-2024:1376-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1376-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/AIPMFBJL5BSZQLVHROWU5JYEILWRTBSN");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'polkit'
  package(s) announced via the SUSE-SU-2024:1376-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for polkit fixes the following issues:

  * Change permissions for rules folders (bsc#1209282)

  ##");

  script_tag(name:"affected", value:"'polkit' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"polkit-devel-121", rpm:"polkit-devel-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pkexec-debuginfo-121", rpm:"pkexec-debuginfo-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Polkit-1_0-121", rpm:"typelib-1_0-Polkit-1_0-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"polkit-devel-debuginfo-121", rpm:"polkit-devel-debuginfo-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"polkit-121", rpm:"polkit-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"polkit-debugsource-121", rpm:"polkit-debugsource-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"polkit-debuginfo-121", rpm:"polkit-debuginfo-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit-agent-1-0-debuginfo-121", rpm:"libpolkit-agent-1-0-debuginfo-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit-gobject-1-0-debuginfo-121", rpm:"libpolkit-gobject-1-0-debuginfo-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit-gobject-1-0-121", rpm:"libpolkit-gobject-1-0-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit-agent-1-0-121", rpm:"libpolkit-agent-1-0-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pkexec-121", rpm:"pkexec-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit-agent-1-0-32bit-debuginfo-121", rpm:"libpolkit-agent-1-0-32bit-debuginfo-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit-agent-1-0-32bit-121", rpm:"libpolkit-agent-1-0-32bit-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit-gobject-1-0-32bit-121", rpm:"libpolkit-gobject-1-0-32bit-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit-gobject-1-0-32bit-debuginfo-121", rpm:"libpolkit-gobject-1-0-32bit-debuginfo-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"polkit-doc-121", rpm:"polkit-doc-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit-gobject-1-0-64bit-121", rpm:"libpolkit-gobject-1-0-64bit-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit-gobject-1-0-64bit-debuginfo-121", rpm:"libpolkit-gobject-1-0-64bit-debuginfo-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit-agent-1-0-64bit-debuginfo-121", rpm:"libpolkit-agent-1-0-64bit-debuginfo-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit-agent-1-0-64bit-121", rpm:"libpolkit-agent-1-0-64bit-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"polkit-devel-121", rpm:"polkit-devel-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pkexec-debuginfo-121", rpm:"pkexec-debuginfo-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Polkit-1_0-121", rpm:"typelib-1_0-Polkit-1_0-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"polkit-devel-debuginfo-121", rpm:"polkit-devel-debuginfo-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"polkit-121", rpm:"polkit-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"polkit-debugsource-121", rpm:"polkit-debugsource-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"polkit-debuginfo-121", rpm:"polkit-debuginfo-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit-agent-1-0-debuginfo-121", rpm:"libpolkit-agent-1-0-debuginfo-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit-gobject-1-0-debuginfo-121", rpm:"libpolkit-gobject-1-0-debuginfo-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit-gobject-1-0-121", rpm:"libpolkit-gobject-1-0-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit-agent-1-0-121", rpm:"libpolkit-agent-1-0-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pkexec-121", rpm:"pkexec-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit-agent-1-0-32bit-debuginfo-121", rpm:"libpolkit-agent-1-0-32bit-debuginfo-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit-agent-1-0-32bit-121", rpm:"libpolkit-agent-1-0-32bit-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit-gobject-1-0-32bit-121", rpm:"libpolkit-gobject-1-0-32bit-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit-gobject-1-0-32bit-debuginfo-121", rpm:"libpolkit-gobject-1-0-32bit-debuginfo-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"polkit-doc-121", rpm:"polkit-doc-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit-gobject-1-0-64bit-121", rpm:"libpolkit-gobject-1-0-64bit-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit-gobject-1-0-64bit-debuginfo-121", rpm:"libpolkit-gobject-1-0-64bit-debuginfo-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit-agent-1-0-64bit-debuginfo-121", rpm:"libpolkit-agent-1-0-64bit-debuginfo-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolkit-agent-1-0-64bit-121", rpm:"libpolkit-agent-1-0-64bit-121~150500.3.3.1", rls:"openSUSELeap15.5"))) {
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