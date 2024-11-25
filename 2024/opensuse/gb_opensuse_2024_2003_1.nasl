# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856221");
  script_version("2024-06-21T05:05:42+0000");
  script_cve_id("CVE-2024-35235");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-06-21 05:05:42 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-06-15 04:00:38 +0000 (Sat, 15 Jun 2024)");
  script_name("openSUSE: Security Advisory for cups (SUSE-SU-2024:2003-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.6|openSUSELeapMicro5\.3|openSUSELeap15\.5|openSUSELeapMicro5\.4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2003-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6KJM5QRNL4HO626REJXZOUUBMTRWTPTM");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups'
  package(s) announced via the SUSE-SU-2024:2003-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cups fixes the following issues:

  * CVE-2024-35235: Fixed a bug in cupsd that could allow an attacker to change
      the permissions of other files in the system. (bsc#1225365)

  * Handle local 'Negotiate' authentication response for cli clients
      (bsc#1223179)

  ##");

  script_tag(name:"affected", value:"'cups' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"cups-debuginfo", rpm:"cups-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-debugsource", rpm:"cups-debugsource~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsmime1", rpm:"libcupsmime1~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsppdc1-debuginfo", rpm:"libcupsppdc1-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2-debuginfo", rpm:"libcups2-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-ddk-debuginfo", rpm:"cups-ddk-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupscgi1", rpm:"libcupscgi1~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups", rpm:"cups~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupscgi1-debuginfo", rpm:"libcupscgi1-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsppdc1", rpm:"libcupsppdc1~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-client-debuginfo", rpm:"cups-client-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-devel", rpm:"cups-devel~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-ddk", rpm:"cups-ddk~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2", rpm:"libcups2~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-config", rpm:"cups-config~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsimage2", rpm:"libcupsimage2~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-client", rpm:"cups-client~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsmime1-debuginfo", rpm:"libcupsmime1-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsimage2-debuginfo", rpm:"libcupsimage2-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-devel-32bit", rpm:"cups-devel-32bit~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupscgi1-32bit", rpm:"libcupscgi1-32bit~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsimage2-32bit-debuginfo", rpm:"libcupsimage2-32bit-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsppdc1-32bit", rpm:"libcupsppdc1-32bit~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsppdc1-32bit-debuginfo", rpm:"libcupsppdc1-32bit-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsimage2-32bit", rpm:"libcupsimage2-32bit~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsmime1-32bit-debuginfo", rpm:"libcupsmime1-32bit-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2-32bit", rpm:"libcups2-32bit~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsmime1-32bit", rpm:"libcupsmime1-32bit~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupscgi1-32bit-debuginfo", rpm:"libcupscgi1-32bit-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2-32bit-debuginfo", rpm:"libcups2-32bit-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-debuginfo", rpm:"cups-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-debugsource", rpm:"cups-debugsource~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsmime1", rpm:"libcupsmime1~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsppdc1-debuginfo", rpm:"libcupsppdc1-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2-debuginfo", rpm:"libcups2-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-ddk-debuginfo", rpm:"cups-ddk-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupscgi1", rpm:"libcupscgi1~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups", rpm:"cups~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupscgi1-debuginfo", rpm:"libcupscgi1-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsppdc1", rpm:"libcupsppdc1~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-client-debuginfo", rpm:"cups-client-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-devel", rpm:"cups-devel~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-ddk", rpm:"cups-ddk~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2", rpm:"libcups2~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-config", rpm:"cups-config~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsimage2", rpm:"libcupsimage2~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-client", rpm:"cups-client~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsmime1-debuginfo", rpm:"libcupsmime1-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsimage2-debuginfo", rpm:"libcupsimage2-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-devel-32bit", rpm:"cups-devel-32bit~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupscgi1-32bit", rpm:"libcupscgi1-32bit~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsimage2-32bit-debuginfo", rpm:"libcupsimage2-32bit-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsppdc1-32bit", rpm:"libcupsppdc1-32bit~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsppdc1-32bit-debuginfo", rpm:"libcupsppdc1-32bit-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsimage2-32bit", rpm:"libcupsimage2-32bit~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsmime1-32bit-debuginfo", rpm:"libcupsmime1-32bit-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2-32bit", rpm:"libcups2-32bit~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsmime1-32bit", rpm:"libcupsmime1-32bit~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupscgi1-32bit-debuginfo", rpm:"libcupscgi1-32bit-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2-32bit-debuginfo", rpm:"libcups2-32bit-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.6"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"cups-debuginfo", rpm:"cups-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-debugsource", rpm:"cups-debugsource~2.2.7~150000.3.59.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2-debuginfo", rpm:"libcups2-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2", rpm:"libcups2~2.2.7~150000.3.59.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-config", rpm:"cups-config~2.2.7~150000.3.59.1", rls:"openSUSELeapMicro5.3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"cups-debuginfo", rpm:"cups-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-debugsource", rpm:"cups-debugsource~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsmime1", rpm:"libcupsmime1~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsppdc1-debuginfo", rpm:"libcupsppdc1-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2-debuginfo", rpm:"libcups2-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-ddk-debuginfo", rpm:"cups-ddk-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupscgi1", rpm:"libcupscgi1~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups", rpm:"cups~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupscgi1-debuginfo", rpm:"libcupscgi1-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsppdc1", rpm:"libcupsppdc1~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-client-debuginfo", rpm:"cups-client-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-devel", rpm:"cups-devel~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-ddk", rpm:"cups-ddk~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2", rpm:"libcups2~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-config", rpm:"cups-config~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsimage2", rpm:"libcupsimage2~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-client", rpm:"cups-client~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsmime1-debuginfo", rpm:"libcupsmime1-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsimage2-debuginfo", rpm:"libcupsimage2-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-devel-32bit", rpm:"cups-devel-32bit~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupscgi1-32bit", rpm:"libcupscgi1-32bit~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsimage2-32bit-debuginfo", rpm:"libcupsimage2-32bit-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsppdc1-32bit", rpm:"libcupsppdc1-32bit~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsppdc1-32bit-debuginfo", rpm:"libcupsppdc1-32bit-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsimage2-32bit", rpm:"libcupsimage2-32bit~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsmime1-32bit-debuginfo", rpm:"libcupsmime1-32bit-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2-32bit", rpm:"libcups2-32bit~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsmime1-32bit", rpm:"libcupsmime1-32bit~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupscgi1-32bit-debuginfo", rpm:"libcupscgi1-32bit-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2-32bit-debuginfo", rpm:"libcups2-32bit-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-debuginfo", rpm:"cups-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-debugsource", rpm:"cups-debugsource~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsmime1", rpm:"libcupsmime1~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsppdc1-debuginfo", rpm:"libcupsppdc1-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2-debuginfo", rpm:"libcups2-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-ddk-debuginfo", rpm:"cups-ddk-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupscgi1", rpm:"libcupscgi1~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups", rpm:"cups~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupscgi1-debuginfo", rpm:"libcupscgi1-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsppdc1", rpm:"libcupsppdc1~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-client-debuginfo", rpm:"cups-client-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-devel", rpm:"cups-devel~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-ddk", rpm:"cups-ddk~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2", rpm:"libcups2~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-config", rpm:"cups-config~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsimage2", rpm:"libcupsimage2~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-client", rpm:"cups-client~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsmime1-debuginfo", rpm:"libcupsmime1-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsimage2-debuginfo", rpm:"libcupsimage2-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-devel-32bit", rpm:"cups-devel-32bit~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupscgi1-32bit", rpm:"libcupscgi1-32bit~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsimage2-32bit-debuginfo", rpm:"libcupsimage2-32bit-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsppdc1-32bit", rpm:"libcupsppdc1-32bit~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsppdc1-32bit-debuginfo", rpm:"libcupsppdc1-32bit-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsimage2-32bit", rpm:"libcupsimage2-32bit~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsmime1-32bit-debuginfo", rpm:"libcupsmime1-32bit-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2-32bit", rpm:"libcups2-32bit~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupsmime1-32bit", rpm:"libcupsmime1-32bit~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcupscgi1-32bit-debuginfo", rpm:"libcupscgi1-32bit-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2-32bit-debuginfo", rpm:"libcups2-32bit-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeap15.5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"cups-debuginfo", rpm:"cups-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-debugsource", rpm:"cups-debugsource~2.2.7~150000.3.59.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2-debuginfo", rpm:"libcups2-debuginfo~2.2.7~150000.3.59.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcups2", rpm:"libcups2~2.2.7~150000.3.59.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-config", rpm:"cups-config~2.2.7~150000.3.59.1", rls:"openSUSELeapMicro5.4"))) {
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