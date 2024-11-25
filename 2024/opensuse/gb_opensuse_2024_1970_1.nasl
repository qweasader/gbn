# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856213");
  script_version("2024-06-21T05:05:42+0000");
  script_cve_id("CVE-2024-24789", "CVE-2024-24790");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-21 05:05:42 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-18 17:59:12 +0000 (Tue, 18 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-06-12 04:00:42 +0000 (Wed, 12 Jun 2024)");
  script_name("openSUSE: Security Advisory for go1.22 (SUSE-SU-2024:1970-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.6|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1970-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KJOHEL7AJ3Y53DS5M4CQSOASW7XQM6ZX");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.22'
  package(s) announced via the SUSE-SU-2024:1970-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.22 fixes the following issues:

  go1.21.11 release (bsc#1212475).

  * CVE-2024-24789: Fixed mishandling of corrupt central directory record in
      archive/zip (bsc#1225973).

  * CVE-2024-24790: Fixed unexpected behavior from Is methods for IPv4-mapped
      IPv6 addresses (bsc#1225974).

  ##");

  script_tag(name:"affected", value:"'go1.22' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"go1.22", rpm:"go1.22~1.22.4~150000.1.18.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.22-doc", rpm:"go1.22-doc~1.22.4~150000.1.18.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.22-race", rpm:"go1.22-race~1.22.4~150000.1.18.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.22", rpm:"go1.22~1.22.4~150000.1.18.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.22-doc", rpm:"go1.22-doc~1.22.4~150000.1.18.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.22-race", rpm:"go1.22-race~1.22.4~150000.1.18.1", rls:"openSUSELeap15.6"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"go1.22", rpm:"go1.22~1.22.4~150000.1.18.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.22-doc", rpm:"go1.22-doc~1.22.4~150000.1.18.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.22-race", rpm:"go1.22-race~1.22.4~150000.1.18.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.22", rpm:"go1.22~1.22.4~150000.1.18.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.22-doc", rpm:"go1.22-doc~1.22.4~150000.1.18.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.22-race", rpm:"go1.22-race~1.22.4~150000.1.18.1", rls:"openSUSELeap15.5"))) {
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