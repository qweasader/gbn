# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856377");
  script_version("2024-08-23T05:05:37+0000");
  script_cve_id("CVE-2024-34402", "CVE-2024-3440", "CVE-2024-34403");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-08-23 05:05:37 +0000 (Fri, 23 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-08-20 04:08:42 +0000 (Tue, 20 Aug 2024)");
  script_name("openSUSE: Security Advisory for uriparser (SUSE-SU-2024:1860-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.6|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1860-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/RFD475ZHZHSU3GMTN4RL2RT5AZTDWMN6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'uriparser'
  package(s) announced via the SUSE-SU-2024:1860-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for uriparser fixes the following issues:

  * CVE-2024-34402: Fixed integer overflow protection in ComposeQueryEngine
      (bsc#1223887).

  * CVE-2024-34403: Fixed integer overflow protection in ComposeQueryMallocExMm
      (bsc#1223888).

  ##");

  script_tag(name:"affected", value:"'uriparser' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"uriparser-debugsource", rpm:"uriparser-debugsource~0.8.5~150000.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uriparser", rpm:"uriparser~0.8.5~150000.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liburiparser1", rpm:"liburiparser1~0.8.5~150000.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liburiparser1-debuginfo", rpm:"liburiparser1-debuginfo~0.8.5~150000.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uriparser-devel", rpm:"uriparser-devel~0.8.5~150000.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uriparser-debuginfo", rpm:"uriparser-debuginfo~0.8.5~150000.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liburiparser1-32bit-debuginfo", rpm:"liburiparser1-32bit-debuginfo~0.8.5~150000.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liburiparser1-32bit", rpm:"liburiparser1-32bit~0.8.5~150000.3.8.1##", rls:"openSUSELeap15.6"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"uriparser-debugsource", rpm:"uriparser-debugsource~0.8.5~150000.3.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uriparser", rpm:"uriparser~0.8.5~150000.3.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liburiparser1", rpm:"liburiparser1~0.8.5~150000.3.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liburiparser1-debuginfo", rpm:"liburiparser1-debuginfo~0.8.5~150000.3.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uriparser-devel", rpm:"uriparser-devel~0.8.5~150000.3.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uriparser-debuginfo", rpm:"uriparser-debuginfo~0.8.5~150000.3.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liburiparser1-32bit-debuginfo", rpm:"liburiparser1-32bit-debuginfo~0.8.5~150000.3.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liburiparser1-32bit", rpm:"liburiparser1-32bit~0.8.5~150000.3.8.1", rls:"openSUSELeap15.5"))) {
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