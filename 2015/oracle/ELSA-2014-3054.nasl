# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123346");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2012-6647", "CVE-2014-0196", "CVE-2014-3144", "CVE-2014-3145");
  script_tag(name:"creation_date", value:"2015-10-06 11:02:34 +0000 (Tue, 06 Oct 2015)");
  script_version("2023-05-18T09:08:59+0000");
  script_tag(name:"last_modification", value:"2023-05-18 09:08:59 +0000 (Thu, 18 May 2023)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2014-3054)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux5|OracleLinux6)");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-3054");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-3054.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-uek, mlnx_en-2.6.32-400.36.6.el5uek, mlnx_en-2.6.32-400.36.6.el6uek, ofa-2.6.32-400.36.6.el5uek, ofa-2.6.32-400.36.6.el6uek' package(s) announced via the ELSA-2014-3054 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"kernel-uek
[2.6.32-400.36.6uek]
- filter: prevent nla extensions to peek beyond the end of the message (Mathias Krause) [Orabug: 19315783] {CVE-2014-3144} {CVE-2014-3145}
- futex: Forbid uaddr == uaddr2 in futex_wait_requeue_pi() (Darren Hart) [Orabug: 19315318] {CVE-2012-6647}

[2.6.32-400.36.5uek]
- n_tty: Fix n_tty_write crash when echoing in raw mode (Peter Hurley) [Orabug: 18756450] {CVE-2014-0196} {CVE-2014-0196}");

  script_tag(name:"affected", value:"'kernel-uek, mlnx_en-2.6.32-400.36.6.el5uek, mlnx_en-2.6.32-400.36.6.el6uek, ofa-2.6.32-400.36.6.el5uek, ofa-2.6.32-400.36.6.el6uek' package(s) on Oracle Linux 5, Oracle Linux 6.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.32~400.36.6.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.32~400.36.6.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.32~400.36.6.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.32~400.36.6.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.32~400.36.6.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.32~400.36.6.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-headers", rpm:"kernel-uek-headers~2.6.32~400.36.6.el5uek", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlnx_en-2.6.32-400.36.6.el5uek", rpm:"mlnx_en-2.6.32-400.36.6.el5uek~1.5.7~2", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlnx_en-2.6.32-400.36.6.el5uekdebug", rpm:"mlnx_en-2.6.32-400.36.6.el5uekdebug~1.5.7~2", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-400.36.6.el5uek", rpm:"ofa-2.6.32-400.36.6.el5uek~1.5.1~4.0.58", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-400.36.6.el5uekdebug", rpm:"ofa-2.6.32-400.36.6.el5uekdebug~1.5.1~4.0.58", rls:"OracleLinux5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.32~400.36.6.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.32~400.36.6.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.32~400.36.6.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.32~400.36.6.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.32~400.36.6.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.32~400.36.6.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-uek-headers", rpm:"kernel-uek-headers~2.6.32~400.36.6.el6uek", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlnx_en-2.6.32-400.36.6.el6uek", rpm:"mlnx_en-2.6.32-400.36.6.el6uek~1.5.7~0.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlnx_en-2.6.32-400.36.6.el6uekdebug", rpm:"mlnx_en-2.6.32-400.36.6.el6uekdebug~1.5.7~0.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-400.36.6.el6uek", rpm:"ofa-2.6.32-400.36.6.el6uek~1.5.1~4.0.58", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ofa-2.6.32-400.36.6.el6uekdebug", rpm:"ofa-2.6.32-400.36.6.el6uekdebug~1.5.1~4.0.58", rls:"OracleLinux6"))) {
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
