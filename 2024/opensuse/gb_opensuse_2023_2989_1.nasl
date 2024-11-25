# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833141");
  script_version("2024-05-16T05:05:35+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"creation_date", value:"2024-03-04 07:59:40 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for conmon (SUSE-SU-2023:2989-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeapMicro5\.3|openSUSELeapMicro5\.4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2989-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3AAFA4BM5JUSS32WBACFWHF3QRMFUGUC");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'conmon'
  package(s) announced via the SUSE-SU-2023:2989-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for conmon fixes the following issues:

  conmon was updated to version 2.1.7:

  * Bumped go version to 1.19 (bsc#1209307).

  Bugfixes:

  * Fixed leaking symbolic links in the opt_socket_path directory.

  * Fixed cgroup oom issues (bsc#1208737).

  * Fixed OOM watcher for cgroupv2 `oom_kill` events.

  ##");

  script_tag(name:"affected", value:"'conmon' package(s) on openSUSE Leap 15.4, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"conmon-debuginfo", rpm:"conmon-debuginfo~2.1.7~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"conmon", rpm:"conmon~2.1.7~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"conmon-debuginfo", rpm:"conmon-debuginfo~2.1.7~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"conmon", rpm:"conmon~2.1.7~150400.3.11.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"conmon-debuginfo", rpm:"conmon-debuginfo~2.1.7~150400.3.11.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"conmon", rpm:"conmon~2.1.7~150400.3.11.1", rls:"openSUSELeapMicro5.3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"conmon-debuginfo", rpm:"conmon-debuginfo~2.1.7~150400.3.11.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"conmon", rpm:"conmon~2.1.7~150400.3.11.1", rls:"openSUSELeapMicro5.4"))) {
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