# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123710");
  script_cve_id("CVE-2011-2166", "CVE-2011-2167", "CVE-2011-4318");
  script_tag(name:"creation_date", value:"2015-10-06 11:07:31 +0000 (Tue, 06 Oct 2015)");
  script_version("2023-10-06T16:09:51+0000");
  script_tag(name:"last_modification", value:"2023-10-06 16:09:51 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2013-0520)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0520");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0520.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dovecot' package(s) announced via the ELSA-2013-0520 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1:2.0.9-5]
- script-login did not drop privileges correctly (#709095)
- fix directory traversal due to not obeying chroot directive (#709097)
- check proxy destination host against SSL certificate name (#754980)

[1:2.0.9-4]
- dovecot may not set correct permissions for mail folder (#697620)

[1:2.0.9-3]
- fix potential crash when parsing header names that contain NUL characters (#728673)");

  script_tag(name:"affected", value:"'dovecot' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"dovecot", rpm:"dovecot~2.0.9~5.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-devel", rpm:"dovecot-devel~2.0.9~5.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-mysql", rpm:"dovecot-mysql~2.0.9~5.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-pgsql", rpm:"dovecot-pgsql~2.0.9~5.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-pigeonhole", rpm:"dovecot-pigeonhole~2.0.9~5.el6", rls:"OracleLinux6"))) {
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
