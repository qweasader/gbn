# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.0695.1");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:00 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:0695-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1|SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:0695-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20170695-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dbus-1' package(s) announced via the SUSE-SU-2017:0695-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dbus-1 fixes the following issues:
Security issues fixed:
- Symlink attack in nonce-tcp transport. (bsc#1025950)
- Symlink attack in unit tests. (bsc#1025951)
Bugfixes:
- Remove sysvinit script, not used under systemd. (bsc#974092)");

  script_tag(name:"affected", value:"'dbus-1' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP1, SUSE Linux Enterprise Software Development Kit 12-SP2.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"dbus-1", rpm:"dbus-1~1.8.22~24.8.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-1-debuginfo", rpm:"dbus-1-debuginfo~1.8.22~24.8.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-1-debuginfo-32bit", rpm:"dbus-1-debuginfo-32bit~1.8.22~24.8.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-1-debugsource", rpm:"dbus-1-debugsource~1.8.22~24.8.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-1-x11", rpm:"dbus-1-x11~1.8.22~24.8.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-1-x11-debuginfo", rpm:"dbus-1-x11-debuginfo~1.8.22~24.8.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-1-x11-debugsource", rpm:"dbus-1-x11-debugsource~1.8.22~24.8.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbus-1-3", rpm:"libdbus-1-3~1.8.22~24.8.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbus-1-3-32bit", rpm:"libdbus-1-3-32bit~1.8.22~24.8.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbus-1-3-debuginfo", rpm:"libdbus-1-3-debuginfo~1.8.22~24.8.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbus-1-3-debuginfo-32bit", rpm:"libdbus-1-3-debuginfo-32bit~1.8.22~24.8.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"dbus-1", rpm:"dbus-1~1.8.22~24.8.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-1-debuginfo", rpm:"dbus-1-debuginfo~1.8.22~24.8.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-1-debuginfo-32bit", rpm:"dbus-1-debuginfo-32bit~1.8.22~24.8.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-1-debugsource", rpm:"dbus-1-debugsource~1.8.22~24.8.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-1-x11", rpm:"dbus-1-x11~1.8.22~24.8.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-1-x11-debuginfo", rpm:"dbus-1-x11-debuginfo~1.8.22~24.8.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dbus-1-x11-debugsource", rpm:"dbus-1-x11-debugsource~1.8.22~24.8.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbus-1-3", rpm:"libdbus-1-3~1.8.22~24.8.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbus-1-3-32bit", rpm:"libdbus-1-3-32bit~1.8.22~24.8.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbus-1-3-debuginfo", rpm:"libdbus-1-3-debuginfo~1.8.22~24.8.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdbus-1-3-debuginfo-32bit", rpm:"libdbus-1-3-debuginfo-32bit~1.8.22~24.8.1", rls:"SLES12.0SP2"))) {
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
