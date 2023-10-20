# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0156");
  script_cve_id("CVE-2019-6109", "CVE-2019-6111");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-24 18:12:00 +0000 (Fri, 24 Mar 2023)");

  script_name("Mageia: Security Advisory (MGASA-2019-0156)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0156");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0156.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24308");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4387");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh' package(s) announced via the MGASA-2019-0156 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated openssh packages fix security vulnerabilities:

Due to missing character encoding in the progress display, the object
name can be used to manipulate the client output, for example to employ
ANSI codes to hide additional files being transferred (CVE-2019-6109).

Due to scp client insufficient input validation in path names sent by
server, a malicious server can do arbitrary file overwrites in target
directory. If the recursive (-r) option is provided, the server can
also manipulate subdirectories as well (CVE-2019-6111).

The check added in this version can lead to regression if the client and
the server have differences in wildcard expansion rules. If the server is
trusted for that purpose, the check can be disabled with a new -T option
to the scp client.");

  script_tag(name:"affected", value:"'openssh' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"openssh", rpm:"openssh~7.5p1~2.4.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass", rpm:"openssh-askpass~7.5p1~2.4.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass-common", rpm:"openssh-askpass-common~7.5p1~2.4.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass-gnome", rpm:"openssh-askpass-gnome~7.5p1~2.4.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-clients", rpm:"openssh-clients~7.5p1~2.4.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-ldap", rpm:"openssh-ldap~7.5p1~2.4.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-server", rpm:"openssh-server~7.5p1~2.4.mga6", rls:"MAGEIA6"))) {
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
