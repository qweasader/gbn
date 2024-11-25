# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1821.1");
  script_cve_id("CVE-2015-5288", "CVE-2015-5289");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1821-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1821-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151821-1/");
  script_xref(name:"URL", value:"http://www.postgresql.org/docs/current/static/release-9-3-10.html");
  script_xref(name:"URL", value:"http://www.postgresql.org/docs/9.3/static/release-9-3-9.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql93' package(s) announced via the SUSE-SU-2015:1821-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The PostreSQL database postgresql93 was updated to the bugfix release 9.3.10:
Security issues fixed:
- CVE-2015-5289, bsc#949670: json or jsonb input values constructed from
 arbitrary user input can crash the PostgreSQL server and cause a denial
 of service.
- CVE-2015-5288, bsc#949669: The crypt() function included with the
 optional pgCrypto extension could be exploited to read a few additional
 bytes of memory. No working exploit for this issue has been developed.
For the full release notes, see:
[link moved to references] Other bugs fixed:
* Move systemd related stuff and user creation to postgresql-init.
* Remove some obsolete %suse_version conditionals.
* Relax dependency on libpq to major version.
* Fix possible failure to recover from an inconsistent database state. See
 full release notes for details.
* Fix rare failure to invalidate relation cache init file.
* Avoid deadlock between incoming sessions and CREATE/DROP DATABASE.
* Improve planner's cost estimates for semi-joins and anti-joins with
 inner indexscans
* For the full release notes for 9.3.9 see:
 [link moved to references]");

  script_tag(name:"affected", value:"'postgresql93' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Software Development Kit 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"postgresql93", rpm:"postgresql93~9.3.10~11.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-contrib", rpm:"postgresql93-contrib~9.3.10~11.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-contrib-debuginfo", rpm:"postgresql93-contrib-debuginfo~9.3.10~11.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-debuginfo", rpm:"postgresql93-debuginfo~9.3.10~11.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-debugsource", rpm:"postgresql93-debugsource~9.3.10~11.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-docs", rpm:"postgresql93-docs~9.3.10~11.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-libs-debugsource", rpm:"postgresql93-libs-debugsource~9.3.10~11.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-server", rpm:"postgresql93-server~9.3.10~11.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql93-server-debuginfo", rpm:"postgresql93-server-debuginfo~9.3.10~11.1", rls:"SLES12.0"))) {
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
