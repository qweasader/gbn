# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833106");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2023-48795");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-28 18:26:44 +0000 (Thu, 28 Dec 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 12:56:21 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for libssh2_org (SUSE-SU-2024:0558-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeapMicro5\.3|openSUSELeap15\.5|openSUSELeapMicro5\.4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0558-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/Q2WISZFQTGNERQG5AXKXZYQG6C6EKV5V");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libssh2_org'
  package(s) announced via the SUSE-SU-2024:0558-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libssh2_org fixes the following issues:

  * Always add the KEX pseudo-methods 'ext-info-c' and 'kex-strict-
      c-v00@openssh.com' when configuring custom method list. [bsc#1218971,
      CVE-2023-48795]

  * The strict-kex extension is announced in the list of available KEX methods.
      However, when the default KEX method list is modified or replaced, the
      extension is not added back automatically.

  ##");

  script_tag(name:"affected", value:"'libssh2_org' package(s) on openSUSE Leap 15.5, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

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

if(release == "openSUSELeapMicro5.3") {

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1", rpm:"libssh2-1~1.11.0~150000.4.25.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1-debuginfo", rpm:"libssh2-1-debuginfo~1.11.0~150000.4.25.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2_org-debugsource", rpm:"libssh2_org-debugsource~1.11.0~150000.4.25.1", rls:"openSUSELeapMicro5.3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1", rpm:"libssh2-1~1.11.0~150000.4.25.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1-debuginfo", rpm:"libssh2-1-debuginfo~1.11.0~150000.4.25.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-devel", rpm:"libssh2-devel~1.11.0~150000.4.25.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2_org-debugsource", rpm:"libssh2_org-debugsource~1.11.0~150000.4.25.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1-32bit", rpm:"libssh2-1-32bit~1.11.0~150000.4.25.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1-32bit-debuginfo", rpm:"libssh2-1-32bit-debuginfo~1.11.0~150000.4.25.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1", rpm:"libssh2-1~1.11.0~150000.4.25.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1-debuginfo", rpm:"libssh2-1-debuginfo~1.11.0~150000.4.25.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-devel", rpm:"libssh2-devel~1.11.0~150000.4.25.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2_org-debugsource", rpm:"libssh2_org-debugsource~1.11.0~150000.4.25.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1-32bit", rpm:"libssh2-1-32bit~1.11.0~150000.4.25.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1-32bit-debuginfo", rpm:"libssh2-1-32bit-debuginfo~1.11.0~150000.4.25.1", rls:"openSUSELeap15.5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1", rpm:"libssh2-1~1.11.0~150000.4.25.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-1-debuginfo", rpm:"libssh2-1-debuginfo~1.11.0~150000.4.25.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2_org-debugsource", rpm:"libssh2_org-debugsource~1.11.0~150000.4.25.1", rls:"openSUSELeapMicro5.4"))) {
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