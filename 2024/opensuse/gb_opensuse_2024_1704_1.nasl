# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856148");
  script_version("2024-06-07T15:38:39+0000");
  script_cve_id("CVE-2019-6462");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-06-07 15:38:39 +0000 (Fri, 07 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-18 14:26:09 +0000 (Fri, 18 Jan 2019)");
  script_tag(name:"creation_date", value:"2024-05-24 01:00:23 +0000 (Fri, 24 May 2024)");
  script_name("openSUSE: Security Advisory for cairo (SUSE-SU-2024:1704-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5|openSUSELeapMicro5\.3|openSUSELeapMicro5\.4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1704-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/RFQ4EM4H2CDBFQZ3K46CFJF3JNEPDQ2T");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cairo'
  package(s) announced via the SUSE-SU-2024:1704-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cairo fixes the following issues:

  * CVE-2019-6462: Fixed a potentially infinite loop (bsc#1122321).

  ##");

  script_tag(name:"affected", value:"'cairo' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libcairo-script-interpreter2-debuginfo", rpm:"libcairo-script-interpreter2-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cairo-devel", rpm:"cairo-devel~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo2-debuginfo", rpm:"libcairo2-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cairo-debugsource", rpm:"cairo-debugsource~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo2", rpm:"libcairo2~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-gobject2", rpm:"libcairo-gobject2~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-script-interpreter2", rpm:"libcairo-script-interpreter2~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cairo-tools", rpm:"cairo-tools~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-gobject2-debuginfo", rpm:"libcairo-gobject2-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cairo-tools-debuginfo", rpm:"cairo-tools-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-gobject2-32bit-debuginfo", rpm:"libcairo-gobject2-32bit-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo2-32bit-debuginfo", rpm:"libcairo2-32bit-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-script-interpreter2-32bit", rpm:"libcairo-script-interpreter2-32bit~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-gobject2-32bit", rpm:"libcairo-gobject2-32bit~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo2-32bit", rpm:"libcairo2-32bit~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cairo-devel-32bit", rpm:"cairo-devel-32bit~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-script-interpreter2-32bit-debuginfo", rpm:"libcairo-script-interpreter2-32bit-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-gobject2-64bit-debuginfo", rpm:"libcairo-gobject2-64bit-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-gobject2-64bit", rpm:"libcairo-gobject2-64bit~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo2-64bit", rpm:"libcairo2-64bit~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo2-64bit-debuginfo", rpm:"libcairo2-64bit-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-script-interpreter2-64bit-debuginfo", rpm:"libcairo-script-interpreter2-64bit-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-script-interpreter2-64bit", rpm:"libcairo-script-interpreter2-64bit~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cairo-devel-64bit", rpm:"cairo-devel-64bit~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-script-interpreter2-debuginfo", rpm:"libcairo-script-interpreter2-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cairo-devel", rpm:"cairo-devel~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo2-debuginfo", rpm:"libcairo2-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cairo-debugsource", rpm:"cairo-debugsource~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo2", rpm:"libcairo2~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-gobject2", rpm:"libcairo-gobject2~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-script-interpreter2", rpm:"libcairo-script-interpreter2~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cairo-tools", rpm:"cairo-tools~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-gobject2-debuginfo", rpm:"libcairo-gobject2-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cairo-tools-debuginfo", rpm:"cairo-tools-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-gobject2-32bit-debuginfo", rpm:"libcairo-gobject2-32bit-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo2-32bit-debuginfo", rpm:"libcairo2-32bit-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-script-interpreter2-32bit", rpm:"libcairo-script-interpreter2-32bit~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-gobject2-32bit", rpm:"libcairo-gobject2-32bit~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo2-32bit", rpm:"libcairo2-32bit~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cairo-devel-32bit", rpm:"cairo-devel-32bit~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-script-interpreter2-32bit-debuginfo", rpm:"libcairo-script-interpreter2-32bit-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-gobject2-64bit-debuginfo", rpm:"libcairo-gobject2-64bit-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-gobject2-64bit", rpm:"libcairo-gobject2-64bit~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo2-64bit", rpm:"libcairo2-64bit~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo2-64bit-debuginfo", rpm:"libcairo2-64bit-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-script-interpreter2-64bit-debuginfo", rpm:"libcairo-script-interpreter2-64bit-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-script-interpreter2-64bit", rpm:"libcairo-script-interpreter2-64bit~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cairo-devel-64bit", rpm:"cairo-devel-64bit~1.16.0~150400.11.3.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libcairo-script-interpreter2-debuginfo", rpm:"libcairo-script-interpreter2-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cairo-devel", rpm:"cairo-devel~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo2-debuginfo", rpm:"libcairo2-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cairo-debugsource", rpm:"cairo-debugsource~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo2", rpm:"libcairo2~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-gobject2", rpm:"libcairo-gobject2~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-script-interpreter2", rpm:"libcairo-script-interpreter2~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cairo-tools", rpm:"cairo-tools~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-gobject2-debuginfo", rpm:"libcairo-gobject2-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cairo-tools-debuginfo", rpm:"cairo-tools-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-gobject2-32bit-debuginfo", rpm:"libcairo-gobject2-32bit-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo2-32bit-debuginfo", rpm:"libcairo2-32bit-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-script-interpreter2-32bit", rpm:"libcairo-script-interpreter2-32bit~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-gobject2-32bit", rpm:"libcairo-gobject2-32bit~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo2-32bit", rpm:"libcairo2-32bit~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cairo-devel-32bit", rpm:"cairo-devel-32bit~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-script-interpreter2-32bit-debuginfo", rpm:"libcairo-script-interpreter2-32bit-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-script-interpreter2-debuginfo", rpm:"libcairo-script-interpreter2-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cairo-devel", rpm:"cairo-devel~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo2-debuginfo", rpm:"libcairo2-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cairo-debugsource", rpm:"cairo-debugsource~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo2", rpm:"libcairo2~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-gobject2", rpm:"libcairo-gobject2~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-script-interpreter2", rpm:"libcairo-script-interpreter2~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cairo-tools", rpm:"cairo-tools~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-gobject2-debuginfo", rpm:"libcairo-gobject2-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cairo-tools-debuginfo", rpm:"cairo-tools-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-gobject2-32bit-debuginfo", rpm:"libcairo-gobject2-32bit-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo2-32bit-debuginfo", rpm:"libcairo2-32bit-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-script-interpreter2-32bit", rpm:"libcairo-script-interpreter2-32bit~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-gobject2-32bit", rpm:"libcairo-gobject2-32bit~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo2-32bit", rpm:"libcairo2-32bit~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cairo-devel-32bit", rpm:"cairo-devel-32bit~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-script-interpreter2-32bit-debuginfo", rpm:"libcairo-script-interpreter2-32bit-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.3") {

  if(!isnull(res = isrpmvuln(pkg:"libcairo2-debuginfo", rpm:"libcairo2-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo2", rpm:"libcairo2~1.16.0~150400.11.3.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-gobject2", rpm:"libcairo-gobject2~1.16.0~150400.11.3.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-gobject2-debuginfo", rpm:"libcairo-gobject2-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cairo-debugsource", rpm:"cairo-debugsource~1.16.0~150400.11.3.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.4") {

  if(!isnull(res = isrpmvuln(pkg:"libcairo2-debuginfo", rpm:"libcairo2-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo2", rpm:"libcairo2~1.16.0~150400.11.3.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-gobject2", rpm:"libcairo-gobject2~1.16.0~150400.11.3.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcairo-gobject2-debuginfo", rpm:"libcairo-gobject2-debuginfo~1.16.0~150400.11.3.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cairo-debugsource", rpm:"cairo-debugsource~1.16.0~150400.11.3.1", rls:"openSUSELeapMicro5.4"))) {
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