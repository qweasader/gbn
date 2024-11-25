# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833209");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2023-37327");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"creation_date", value:"2024-03-04 07:52:57 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for gstreamer (SUSE-SU-2023:3248-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3248-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/PRZBN5JYJY3LFC2COGRCI73PPNEIAV5M");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer'
  package(s) announced via the SUSE-SU-2023:3248-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gstreamer-plugins-good fixes the following issues:

  * CVE-2023-37327: Fixed FLAC file parsing integer overflow remote code
      execution vulnerability. (bsc#1213128)

  ##");

  script_tag(name:"affected", value:"'gstreamer' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-extra", rpm:"gstreamer-plugins-good-extra~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-debuginfo", rpm:"gstreamer-plugins-good-debuginfo~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-gtk-debuginfo", rpm:"gstreamer-plugins-good-gtk-debuginfo~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-jack-debuginfo", rpm:"gstreamer-plugins-good-jack-debuginfo~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good", rpm:"gstreamer-plugins-good~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-qtqml", rpm:"gstreamer-plugins-good-qtqml~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-jack", rpm:"gstreamer-plugins-good-jack~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-qtqml-debuginfo", rpm:"gstreamer-plugins-good-qtqml-debuginfo~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-debugsource", rpm:"gstreamer-plugins-good-debugsource~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-extra-debuginfo", rpm:"gstreamer-plugins-good-extra-debuginfo~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-gtk", rpm:"gstreamer-plugins-good-gtk~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-extra-32bit", rpm:"gstreamer-plugins-good-extra-32bit~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-extra-32bit-debuginfo", rpm:"gstreamer-plugins-good-extra-32bit-debuginfo~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-32bit", rpm:"gstreamer-plugins-good-32bit~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-jack-32bit-debuginfo", rpm:"gstreamer-plugins-good-jack-32bit-debuginfo~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-jack-32bit", rpm:"gstreamer-plugins-good-jack-32bit~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-32bit-debuginfo", rpm:"gstreamer-plugins-good-32bit-debuginfo~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-lang", rpm:"gstreamer-plugins-good-lang~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-jack-64bit-debuginfo", rpm:"gstreamer-plugins-good-jack-64bit-debuginfo~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-64bit", rpm:"gstreamer-plugins-good-64bit~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-jack-64bit", rpm:"gstreamer-plugins-good-jack-64bit~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-extra-64bit", rpm:"gstreamer-plugins-good-extra-64bit~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-64bit-debuginfo", rpm:"gstreamer-plugins-good-64bit-debuginfo~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-extra-64bit-debuginfo", rpm:"gstreamer-plugins-good-extra-64bit-debuginfo~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-extra", rpm:"gstreamer-plugins-good-extra~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-debuginfo", rpm:"gstreamer-plugins-good-debuginfo~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-gtk-debuginfo", rpm:"gstreamer-plugins-good-gtk-debuginfo~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-jack-debuginfo", rpm:"gstreamer-plugins-good-jack-debuginfo~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good", rpm:"gstreamer-plugins-good~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-qtqml", rpm:"gstreamer-plugins-good-qtqml~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-jack", rpm:"gstreamer-plugins-good-jack~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-qtqml-debuginfo", rpm:"gstreamer-plugins-good-qtqml-debuginfo~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-debugsource", rpm:"gstreamer-plugins-good-debugsource~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-extra-debuginfo", rpm:"gstreamer-plugins-good-extra-debuginfo~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-gtk", rpm:"gstreamer-plugins-good-gtk~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-extra-32bit", rpm:"gstreamer-plugins-good-extra-32bit~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-extra-32bit-debuginfo", rpm:"gstreamer-plugins-good-extra-32bit-debuginfo~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-32bit", rpm:"gstreamer-plugins-good-32bit~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-jack-32bit-debuginfo", rpm:"gstreamer-plugins-good-jack-32bit-debuginfo~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-jack-32bit", rpm:"gstreamer-plugins-good-jack-32bit~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-32bit-debuginfo", rpm:"gstreamer-plugins-good-32bit-debuginfo~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-lang", rpm:"gstreamer-plugins-good-lang~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-jack-64bit-debuginfo", rpm:"gstreamer-plugins-good-jack-64bit-debuginfo~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-64bit", rpm:"gstreamer-plugins-good-64bit~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-jack-64bit", rpm:"gstreamer-plugins-good-jack-64bit~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-extra-64bit", rpm:"gstreamer-plugins-good-extra-64bit~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-64bit-debuginfo", rpm:"gstreamer-plugins-good-64bit-debuginfo~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-good-extra-64bit-debuginfo", rpm:"gstreamer-plugins-good-extra-64bit-debuginfo~1.22.0~150500.4.3.1", rls:"openSUSELeap15.5"))) {
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