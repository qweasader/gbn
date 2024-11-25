# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856204");
  script_version("2024-06-21T05:05:42+0000");
  script_cve_id("CVE-2024-25062", "CVE-2024-2506");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-06-21 05:05:42 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-13 00:40:40 +0000 (Tue, 13 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-06-12 04:00:29 +0000 (Wed, 12 Jun 2024)");
  script_name("openSUSE: Security Advisory for libxml2 (SUSE-SU-2024:0613-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeapMicro5\.3|openSUSELeapMicro5\.4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0613-2");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/LKTFGNNJO2CA3HEPJPYO6A2HGIOZBJPF");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2'
  package(s) announced via the SUSE-SU-2024:0613-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libxml2 fixes the following issues:

  * CVE-2024-25062: Fixed use-after-free in XMLReader (bsc#1219576).

  ##");

  script_tag(name:"affected", value:"'libxml2' package(s) on openSUSE Leap 15.4, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"python3-libxml2-debuginfo", rpm:"python3-libxml2-debuginfo~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-libxml2-debuginfo", rpm:"python311-libxml2-debuginfo~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-python-debugsource", rpm:"libxml2-python-debugsource~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-debuginfo", rpm:"libxml2-2-debuginfo~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libxml2", rpm:"python3-libxml2~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2", rpm:"libxml2-2~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-tools-debuginfo", rpm:"libxml2-tools-debuginfo~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-debugsource", rpm:"libxml2-debugsource~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-libxml2", rpm:"python311-libxml2~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-tools", rpm:"libxml2-tools~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-32bit-debuginfo", rpm:"libxml2-2-32bit-debuginfo~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-devel-32bit", rpm:"libxml2-devel-32bit~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-32bit", rpm:"libxml2-2-32bit~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-doc", rpm:"libxml2-doc~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-devel-64bit", rpm:"libxml2-devel-64bit~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-64bit-debuginfo", rpm:"libxml2-2-64bit-debuginfo~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-64bit", rpm:"libxml2-2-64bit~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libxml2-debuginfo", rpm:"python3-libxml2-debuginfo~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-libxml2-debuginfo", rpm:"python311-libxml2-debuginfo~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-python-debugsource", rpm:"libxml2-python-debugsource~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-debuginfo", rpm:"libxml2-2-debuginfo~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libxml2", rpm:"python3-libxml2~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2", rpm:"libxml2-2~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-tools-debuginfo", rpm:"libxml2-tools-debuginfo~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-debugsource", rpm:"libxml2-debugsource~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-libxml2", rpm:"python311-libxml2~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-tools", rpm:"libxml2-tools~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-32bit-debuginfo", rpm:"libxml2-2-32bit-debuginfo~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-devel-32bit", rpm:"libxml2-devel-32bit~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-32bit", rpm:"libxml2-2-32bit~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-doc", rpm:"libxml2-doc~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-devel-64bit", rpm:"libxml2-devel-64bit~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-64bit-debuginfo", rpm:"libxml2-2-64bit-debuginfo~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-64bit", rpm:"libxml2-2-64bit~2.9.14~150400.5.28.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"python3-libxml2-debuginfo", rpm:"python3-libxml2-debuginfo~2.9.14~150400.5.28.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-python-debugsource", rpm:"libxml2-python-debugsource~2.9.14~150400.5.28.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-debuginfo", rpm:"libxml2-2-debuginfo~2.9.14~150400.5.28.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libxml2", rpm:"python3-libxml2~2.9.14~150400.5.28.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2", rpm:"libxml2-2~2.9.14~150400.5.28.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-tools-debuginfo", rpm:"libxml2-tools-debuginfo~2.9.14~150400.5.28.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-debugsource", rpm:"libxml2-debugsource~2.9.14~150400.5.28.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-tools", rpm:"libxml2-tools~2.9.14~150400.5.28.1", rls:"openSUSELeapMicro5.3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"python3-libxml2-debuginfo", rpm:"python3-libxml2-debuginfo~2.9.14~150400.5.28.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-python-debugsource", rpm:"libxml2-python-debugsource~2.9.14~150400.5.28.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-debuginfo", rpm:"libxml2-2-debuginfo~2.9.14~150400.5.28.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libxml2", rpm:"python3-libxml2~2.9.14~150400.5.28.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2", rpm:"libxml2-2~2.9.14~150400.5.28.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-tools-debuginfo", rpm:"libxml2-tools-debuginfo~2.9.14~150400.5.28.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-debugsource", rpm:"libxml2-debugsource~2.9.14~150400.5.28.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-tools", rpm:"libxml2-tools~2.9.14~150400.5.28.1", rls:"openSUSELeapMicro5.4"))) {
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