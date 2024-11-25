# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856249");
  script_version("2024-07-10T14:21:44+0000");
  script_cve_id("CVE-2024-24786", "CVE-2024-3727");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-07-10 14:21:44 +0000 (Wed, 10 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-06-29 04:00:29 +0000 (Sat, 29 Jun 2024)");
  script_name("openSUSE: Security Advisory for podman (SUSE-SU-2024:2090-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeapMicro5\.3|openSUSELeapMicro5\.4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2090-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ZI77HYBWRIS5I4FNUDRK5TTYJ5BOW2ZJ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'podman'
  package(s) announced via the SUSE-SU-2024:2090-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for podman fixes the following issues:

  * Update to version 4.9.5

  * CVE-2024-3727: Fixed a flaw that allowed attackers to trigger unexpected
      authenticated registry accesses on behalf of a victim user, causing resource
      exhaustion, local path traversal, and other attacks. (bsc#1224122)

  * CVE-2024-24786: Fixed an infinite loop in protojson. (bsc#1226136)

  ##");

  script_tag(name:"affected", value:"'podman' package(s) on openSUSE Leap 15.4, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"podman", rpm:"podman~4.9.5~150400.4.27.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-debuginfo", rpm:"podman-debuginfo~4.9.5~150400.4.27.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-remote", rpm:"podman-remote~4.9.5~150400.4.27.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-remote-debuginfo", rpm:"podman-remote-debuginfo~4.9.5~150400.4.27.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podmansh", rpm:"podmansh~4.9.5~150400.4.27.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-docker", rpm:"podman-docker~4.9.5~150400.4.27.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman", rpm:"podman~4.9.5~150400.4.27.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-debuginfo", rpm:"podman-debuginfo~4.9.5~150400.4.27.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-remote", rpm:"podman-remote~4.9.5~150400.4.27.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-remote-debuginfo", rpm:"podman-remote-debuginfo~4.9.5~150400.4.27.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podmansh", rpm:"podmansh~4.9.5~150400.4.27.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-docker", rpm:"podman-docker~4.9.5~150400.4.27.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"podman", rpm:"podman~4.9.5~150400.4.27.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-debuginfo", rpm:"podman-debuginfo~4.9.5~150400.4.27.1##", rls:"openSUSELeapMicro5.3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"podman", rpm:"podman~4.9.5~150400.4.27.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podman-debuginfo", rpm:"podman-debuginfo~4.9.5~150400.4.27.1", rls:"openSUSELeapMicro5.4"))) {
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