# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856151");
  script_version("2024-06-07T15:38:39+0000");
  script_cve_id("CVE-2024-34069");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-06-07 15:38:39 +0000 (Fri, 07 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-05-24 01:00:33 +0000 (Fri, 24 May 2024)");
  script_name("openSUSE: Security Advisory for python (SUSE-SU-2024:1624-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.5|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1624-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/HYN7QZ7RPM3NW2GXNRZJI6H3IFLBFIOG");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python'
  package(s) announced via the SUSE-SU-2024:1624-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-Werkzeug fixes the following issues:

  * CVE-2024-34069: Fixed a remote code execution through debugger when
      interacting with attacker controlled domain (bsc#1223979).

  ##");

  script_tag(name:"affected", value:"'python' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"python3-Werkzeug", rpm:"python3-Werkzeug~1.0.1~150300.3.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-Werkzeug", rpm:"python3-Werkzeug~1.0.1~150300.3.8.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"python3-Werkzeug", rpm:"python3-Werkzeug~1.0.1~150300.3.8.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-Werkzeug", rpm:"python2-Werkzeug~1.0.1~150300.3.8.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-Werkzeug", rpm:"python3-Werkzeug~1.0.1~150300.3.8.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-Werkzeug", rpm:"python2-Werkzeug~1.0.1~150300.3.8.1", rls:"openSUSELeap15.3"))) {
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