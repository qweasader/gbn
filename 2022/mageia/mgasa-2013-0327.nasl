# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0327");
  script_cve_id("CVE-2013-4495");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Mageia: Security Advisory (MGASA-2013-0327)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(2|3)");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0327");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0327.html");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2796");
  script_xref(name:"URL", value:"http://www.supercluster.org/pipermail/torqueusers/2013-November/016425.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11670");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'torque' package(s) announced via the MGASA-2013-0327 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated torque packages fix security vulnerability:

A user could submit executable shell commands on the tail of what is passed
with the -M switch for qsub. This was later passed to a pipe, making it
possible for these commands to be executed as root on the pbs_server
(CVE-2013-4495).");

  script_tag(name:"affected", value:"'torque' package(s) on Mageia 2, Mageia 3.");

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

if(release == "MAGEIA2") {

  if(!isnull(res = isrpmvuln(pkg:"lib64torque-devel", rpm:"lib64torque-devel~2.5.12~1.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64torque2", rpm:"lib64torque2~2.5.12~1.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtorque-devel", rpm:"libtorque-devel~2.5.12~1.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtorque2", rpm:"libtorque2~2.5.12~1.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"torque", rpm:"torque~2.5.12~1.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"torque-client", rpm:"torque-client~2.5.12~1.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"torque-gui", rpm:"torque-gui~2.5.12~1.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"torque-mom", rpm:"torque-mom~2.5.12~1.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"torque-sched", rpm:"torque-sched~2.5.12~1.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"torque-server", rpm:"torque-server~2.5.12~1.2.mga2", rls:"MAGEIA2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"lib64torque-devel", rpm:"lib64torque-devel~4.1.5.1~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64torque2", rpm:"lib64torque2~4.1.5.1~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtorque-devel", rpm:"libtorque-devel~4.1.5.1~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtorque2", rpm:"libtorque2~4.1.5.1~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"torque", rpm:"torque~4.1.5.1~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"torque-client", rpm:"torque-client~4.1.5.1~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"torque-gui", rpm:"torque-gui~4.1.5.1~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"torque-mom", rpm:"torque-mom~4.1.5.1~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"torque-sched", rpm:"torque-sched~4.1.5.1~1.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"torque-server", rpm:"torque-server~4.1.5.1~1.2.mga3", rls:"MAGEIA3"))) {
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
