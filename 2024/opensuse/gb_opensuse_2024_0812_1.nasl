# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856030");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2023-45289", "CVE-2023-45290", "CVE-2024-24783", "CVE-2024-24784", "CVE-2024-24785");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"creation_date", value:"2024-03-25 09:30:14 +0000 (Mon, 25 Mar 2024)");
  script_name("openSUSE: Security Advisory for go1.22 (SUSE-SU-2024:0812-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0812-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/FUXWHIK6PZT6JNZC4VYIEKJEYV7KZCJI");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.22'
  package(s) announced via the SUSE-SU-2024:0812-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.22 fixes the following issues:

  * Upgrade go to version 1.22.1

  * CVE-2023-45289: net/http, net/http/cookiejar: incorrect forwarding of
      sensitive headers and cookies on HTTP redirect (bsc#1221000)

  * CVE-2023-45290: net/http: memory exhaustion in Request.ParseMultipartForm
      (bsc#1221001)

  * CVE-2024-24783: crypto/x509: Verify panics on certificates with an unknown
      public key algorithm (bsc#1220999)

  * CVE-2024-24784: net/mail: comments in display names are incorrectly handled
      (bsc#1221002)

  * CVE-2024-24785: html/template: errors returned from MarshalJSON methods may
      break template escaping (bsc#1221003)

  ##");

  script_tag(name:"affected", value:"'go1.22' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"go1.22", rpm:"go1.22~1.22.1~150000.1.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.22-doc", rpm:"go1.22-doc~1.22.1~150000.1.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.22-race", rpm:"go1.22-race~1.22.1~150000.1.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.22", rpm:"go1.22~1.22.1~150000.1.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.22-doc", rpm:"go1.22-doc~1.22.1~150000.1.9.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.22-race", rpm:"go1.22-race~1.22.1~150000.1.9.1", rls:"openSUSELeap15.5"))) {
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