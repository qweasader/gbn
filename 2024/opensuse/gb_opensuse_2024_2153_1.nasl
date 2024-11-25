# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856252");
  script_version("2024-07-10T14:21:44+0000");
  script_cve_id("CVE-2024-37535");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-07-10 14:21:44 +0000 (Wed, 10 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-06-29 04:00:35 +0000 (Sat, 29 Jun 2024)");
  script_name("openSUSE: Security Advisory for vte (SUSE-SU-2024:2153-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2153-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/FP54G3O7LDETAMAHVOWZVRV3QMRCGZDP");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vte'
  package(s) announced via the SUSE-SU-2024:2153-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for vte fixes the following issues:

  * CVE-2024-37535: Fixed a bug that allowed an attacker to cause a denial of
      service (memory consumption) via a window resize escape. (bsc#1226134)

  ##");

  script_tag(name:"affected", value:"'vte' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Vte-3_91", rpm:"typelib-1_0-Vte-3_91~0.74.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Vte-2_91", rpm:"typelib-1_0-Vte-2_91~0.74.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvte-2_91-0", rpm:"libvte-2_91-0~0.74.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vte-tools-gtk4", rpm:"vte-tools-gtk4~0.74.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vte-devel", rpm:"vte-devel~0.74.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vte-tools", rpm:"vte-tools~0.74.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvte-2_91-0-debuginfo", rpm:"libvte-2_91-0-debuginfo~0.74.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vte-debuginfo", rpm:"vte-debuginfo~0.74.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vte-tools-debuginfo", rpm:"vte-tools-debuginfo~0.74.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vte-tools-gtk4-debuginfo", rpm:"vte-tools-gtk4-debuginfo~0.74.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vte-debugsource", rpm:"vte-debugsource~0.74.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vte-lang", rpm:"vte-lang~0.74.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Vte-3_91", rpm:"typelib-1_0-Vte-3_91~0.74.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Vte-2_91", rpm:"typelib-1_0-Vte-2_91~0.74.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvte-2_91-0", rpm:"libvte-2_91-0~0.74.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vte-tools-gtk4", rpm:"vte-tools-gtk4~0.74.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vte-devel", rpm:"vte-devel~0.74.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vte-tools", rpm:"vte-tools~0.74.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvte-2_91-0-debuginfo", rpm:"libvte-2_91-0-debuginfo~0.74.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vte-debuginfo", rpm:"vte-debuginfo~0.74.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vte-tools-debuginfo", rpm:"vte-tools-debuginfo~0.74.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vte-tools-gtk4-debuginfo", rpm:"vte-tools-gtk4-debuginfo~0.74.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vte-debugsource", rpm:"vte-debugsource~0.74.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vte-lang", rpm:"vte-lang~0.74.2~150600.3.3.1", rls:"openSUSELeap15.6"))) {
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