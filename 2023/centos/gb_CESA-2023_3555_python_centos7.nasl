# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884295");
  script_version("2023-10-12T05:05:32+0000");
  script_cve_id("CVE-2023-24329");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-27 19:28:00 +0000 (Mon, 27 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-07-30 01:03:02 +0000 (Sun, 30 Jul 2023)");
  script_name("CentOS: Security Advisory for python (CESA-2023:3555)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2023:3555");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2023-July/086400.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python'
  package(s) announced via the CESA-2023:3555 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Python is an interpreted, interactive, object-oriented programming
language, which includes modules, classes, exceptions, very high level
dynamic data types and dynamic typing. Python supports interfaces to many
system calls and libraries, as well as to various windowing systems.

Security Fix(es):

  * python: urllib.parse url blocklisting bypass (CVE-2023-24329)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'python' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"python", rpm:"python~2.7.5~93.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-debug", rpm:"python-debug~2.7.5~93.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-devel", rpm:"python-devel~2.7.5~93.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libs", rpm:"python-libs~2.7.5~93.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-test", rpm:"python-test~2.7.5~93.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tools", rpm:"python-tools~2.7.5~93.el7_9", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tkinter", rpm:"tkinter~2.7.5~93.el7_9", rls:"CentOS7"))) {
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