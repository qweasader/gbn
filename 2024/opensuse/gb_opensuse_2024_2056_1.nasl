# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856236");
  script_version("2024-07-24T05:06:37+0000");
  script_cve_id("CVE-2024-5171");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-24 05:06:37 +0000 (Wed, 24 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-23 18:09:56 +0000 (Tue, 23 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-06-19 04:00:37 +0000 (Wed, 19 Jun 2024)");
  script_name("openSUSE: Security Advisory for libaom (SUSE-SU-2024:2056-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2056-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/I5DKXRLMHFAHYDPFNUROIXADHLJOQBFE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libaom'
  package(s) announced via the SUSE-SU-2024:2056-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libaom fixes the following issues:

  * CVE-2024-5171: Fixed heap buffer overflow in img_alloc_helper() caused by
      integer overflow (bsc#1226020).

  ##");

  script_tag(name:"affected", value:"'libaom' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libaom3-debuginfo", rpm:"libaom3-debuginfo~3.7.1~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaom3", rpm:"libaom3~3.7.1~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aom-tools-debuginfo", rpm:"aom-tools-debuginfo~3.7.1~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaom-debugsource", rpm:"libaom-debugsource~3.7.1~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaom-devel", rpm:"libaom-devel~3.7.1~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aom-tools", rpm:"aom-tools~3.7.1~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaom3-32bit-debuginfo", rpm:"libaom3-32bit-debuginfo~3.7.1~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaom3-32bit", rpm:"libaom3-32bit~3.7.1~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaom-devel-doc", rpm:"libaom-devel-doc~3.7.1~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaom3-64bit", rpm:"libaom3-64bit~3.7.1~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaom3-64bit-debuginfo", rpm:"libaom3-64bit-debuginfo~3.7.1~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaom3-debuginfo", rpm:"libaom3-debuginfo~3.7.1~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaom3", rpm:"libaom3~3.7.1~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aom-tools-debuginfo", rpm:"aom-tools-debuginfo~3.7.1~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaom-debugsource", rpm:"libaom-debugsource~3.7.1~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaom-devel", rpm:"libaom-devel~3.7.1~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aom-tools", rpm:"aom-tools~3.7.1~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaom3-32bit-debuginfo", rpm:"libaom3-32bit-debuginfo~3.7.1~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaom3-32bit", rpm:"libaom3-32bit~3.7.1~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaom-devel-doc", rpm:"libaom-devel-doc~3.7.1~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaom3-64bit", rpm:"libaom3-64bit~3.7.1~150600.3.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaom3-64bit-debuginfo", rpm:"libaom3-64bit-debuginfo~3.7.1~150600.3.3.1", rls:"openSUSELeap15.6"))) {
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