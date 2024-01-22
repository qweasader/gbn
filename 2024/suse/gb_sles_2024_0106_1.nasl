# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0106.1");
  script_cve_id("CVE-2023-5868", "CVE-2023-5869", "CVE-2023-5870");
  script_tag(name:"creation_date", value:"2024-01-16 10:08:43 +0000 (Tue, 16 Jan 2024)");
  script_version("2024-01-17T05:05:30+0000");
  script_tag(name:"last_modification", value:"2024-01-17 05:05:30 +0000 (Wed, 17 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-13 22:15:00 +0000 (Wed, 13 Dec 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0106-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0106-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240106-1/");
  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/2715");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/16/release-16.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/16/release-16-1.html");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/15/release-15-5.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql, postgresql15, postgresql16' package(s) announced via the SUSE-SU-2024:0106-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql, postgresql15, postgresql16 fixes the following issues:
This update ships postgresql 16.
Security issues fixed:

CVE-2023-5868: Fix handling of unknown-type
 arguments in DISTINCT 'any' aggregate functions. This error led
 to a text-type value being interpreted as an unknown-type value
 (that is, a zero-terminated string) at runtime. This could
 result in disclosure of server memory following the text value. (bsc#1216962)
CVE-2023-5869: Detect integer overflow while
 computing new array dimensions. When assigning new elements to
 array subscripts that are outside the current array bounds, an
 undetected integer overflow could occur in edge cases. Memory
 stomps that are potentially exploitable for arbitrary code
 execution are possible, and so is disclosure of server memory. (bsc#1216961)
CVE-2023-5870: Prevent the pg_signal_backend role
 from signalling background workers and autovacuum processes.
 The documentation says that pg_signal_backend cannot issue
 signals to superuser-owned processes. It was able to signal
 these background processes, though, because they advertise a
 role OID of zero. Treat that as indicating superuser ownership.
 The security implications of cancelling one of these process
 types are fairly small so far as the core code goes (we'll just
 start another one), but extensions might add background workers
 that are more vulnerable.
 Also ensure that the is_superuser parameter is set correctly in
 such processes. No specific security consequences are known for
 that oversight, but it might be significant for some extensions.
 (bsc#1216960)

Changes in postgresql16:


Upgrade to 16.1:


[link moved to references]

[link moved to references]

[link moved to references]


Overhaul postgresql-README.SUSE and move it from the binary
 package to the noarch wrapper package.

Change the unix domain socket location from /var/run to /run.

Changes in postgresql15:


Update to 15.5 [link moved to references]


The libs and mini package are now provided by postgresql16.


Overhaul postgresql-README.SUSE and move it from the binary
 package to the noarch wrapper package.

Change the unix domain socket location from /var/run to /run.

Changes in postgresql:

Interlock version and release of all noarch packages except for
 the postgresql-docs.
bsc#1122892: Add a sysconfig variable for initdb.
Overhaul postgresql-README.SUSE and move it from the binary
 package to the noarch wrapper package.
bsc#1179231: Add an explanation for the /tmp -> /run/postgresql
 move and permission change.
Add postgresql-README as a separate source file.
bsc#1209208: Drop hard dependency on systemd bsc#1206796: Refine the distinction of where to use sysusers and
 use bcond to have the expression only in one place.");

  script_tag(name:"affected", value:"'postgresql, postgresql15, postgresql16' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Package Hub 15.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libecpg6", rpm:"libecpg6~16.1~150200.5.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libecpg6-debuginfo", rpm:"libecpg6-debuginfo~16.1~150200.5.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5", rpm:"libpq5~16.1~150200.5.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpq5-debuginfo", rpm:"libpq5-debuginfo~16.1~150200.5.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql", rpm:"postgresql~16~150300.10.18.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-contrib", rpm:"postgresql-contrib~16~150300.10.18.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-devel", rpm:"postgresql-devel~16~150300.10.18.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-docs", rpm:"postgresql-docs~16~150300.10.18.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-plperl", rpm:"postgresql-plperl~16~150300.10.18.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-plpython", rpm:"postgresql-plpython~16~150300.10.18.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-pltcl", rpm:"postgresql-pltcl~16~150300.10.18.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-server", rpm:"postgresql-server~16~150300.10.18.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql-server-devel", rpm:"postgresql-server-devel~16~150300.10.18.3", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15", rpm:"postgresql15~15.5~150200.5.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-contrib", rpm:"postgresql15-contrib~15.5~150200.5.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-contrib-debuginfo", rpm:"postgresql15-contrib-debuginfo~15.5~150200.5.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-debuginfo", rpm:"postgresql15-debuginfo~15.5~150200.5.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-debugsource", rpm:"postgresql15-debugsource~15.5~150200.5.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-devel", rpm:"postgresql15-devel~15.5~150200.5.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-devel-debuginfo", rpm:"postgresql15-devel-debuginfo~15.5~150200.5.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-docs", rpm:"postgresql15-docs~15.5~150200.5.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-plperl", rpm:"postgresql15-plperl~15.5~150200.5.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-plperl-debuginfo", rpm:"postgresql15-plperl-debuginfo~15.5~150200.5.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-plpython", rpm:"postgresql15-plpython~15.5~150200.5.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-plpython-debuginfo", rpm:"postgresql15-plpython-debuginfo~15.5~150200.5.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-pltcl", rpm:"postgresql15-pltcl~15.5~150200.5.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-pltcl-debuginfo", rpm:"postgresql15-pltcl-debuginfo~15.5~150200.5.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-server", rpm:"postgresql15-server~15.5~150200.5.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-server-debuginfo", rpm:"postgresql15-server-debuginfo~15.5~150200.5.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-server-devel", rpm:"postgresql15-server-devel~15.5~150200.5.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql15-server-devel-debuginfo", rpm:"postgresql15-server-devel-debuginfo~15.5~150200.5.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-debuginfo", rpm:"postgresql16-debuginfo~16.1~150200.5.7.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql16-debugsource", rpm:"postgresql16-debugsource~16.1~150200.5.7.1", rls:"SLES15.0SP3"))) {
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
