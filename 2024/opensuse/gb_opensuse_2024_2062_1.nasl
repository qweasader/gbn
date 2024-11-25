# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856233");
  script_version("2024-06-24T05:05:34+0000");
  script_cve_id("CVE-2024-3049");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_tag(name:"last_modification", value:"2024-06-24 05:05:34 +0000 (Mon, 24 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-11 17:54:22 +0000 (Tue, 11 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-06-19 04:00:35 +0000 (Wed, 19 Jun 2024)");
  script_name("openSUSE: Security Advisory for booth (SUSE-SU-2024:2062-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2062-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/NJ4IB234HBWNMTJ3IDQ6HAS7W4NUFKJW");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'booth'
  package(s) announced via the SUSE-SU-2024:2062-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for booth fixes the following issues:

  * CVE-2024-3049: Fixed a vulnerability where a specially crafted hash can lead
      to invalid HMAC being accepted by Booth server. (bsc#1226032)

  ##");

  script_tag(name:"affected", value:"'booth' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"booth-debugsource", rpm:"booth-debugsource~1.0~150300.18.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"booth-debuginfo", rpm:"booth-debuginfo~1.0~150300.18.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"booth", rpm:"booth~1.0~150300.18.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"booth-test", rpm:"booth-test~1.0~150300.18.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"booth-debugsource", rpm:"booth-debugsource~1.0~150300.18.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"booth-debuginfo", rpm:"booth-debuginfo~1.0~150300.18.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"booth", rpm:"booth~1.0~150300.18.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"booth-test", rpm:"booth-test~1.0~150300.18.6.1", rls:"openSUSELeap15.3"))) {
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