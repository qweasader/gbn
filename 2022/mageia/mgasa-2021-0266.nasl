# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0266");
  script_cve_id("CVE-2021-21419");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-27 22:34:00 +0000 (Thu, 27 May 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0266)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0266");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0266.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29009");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4956-1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/2WJFSBPLCNSZNHYQC4QDRDFRTEZRMD2L/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-eventlet' package(s) announced via the MGASA-2021-0266 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated python-eventlet packages fix a security vulnerability:

Eventlet is a concurrent networking library for Python. A websocket
peer may exhaust memory on Eventlet side by sending very large websocket
frames. Malicious peer may exhaust memory on Eventlet side by sending
highly compressed data frame. A patch in version 0.31.0 restricts websocket
frame to reasonable limits. As a workaround, restricting memory usage via
OS limits would help against overall machine exhaustion, but there is no
workaround to protect Eventlet process (CVE-2021-21419).");

  script_tag(name:"affected", value:"'python-eventlet' package(s) on Mageia 7, Mageia 8.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"python-eventlet", rpm:"python-eventlet~0.24.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-eventlet-doc", rpm:"python-eventlet-doc~0.24.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-eventlet", rpm:"python2-eventlet~0.24.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-eventlet", rpm:"python3-eventlet~0.24.1~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"python-eventlet", rpm:"python-eventlet~0.31.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-eventlet-doc", rpm:"python-eventlet-doc~0.31.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-eventlet", rpm:"python3-eventlet~0.31.0~1.mga8", rls:"MAGEIA8"))) {
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
