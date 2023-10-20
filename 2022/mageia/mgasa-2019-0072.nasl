# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0072");
  script_cve_id("CVE-2019-3814");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-14 03:29:00 +0000 (Fri, 14 Jun 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0072)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0072");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0072.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24314");
  script_xref(name:"URL", value:"https://www.dovecot.org/list/dovecot-news/2019-February/000393.html");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2019/02/05/1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4385");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dovecot' package(s) announced via the MGASA-2019-0072 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2019-3814: If imap/pop3/managesieve/submission client has trusted
certificate with missing username field (ssl_cert_username_field), under
some configurations Dovecot mistakenly trusts the username provided via
authentication instead of failing.");

  script_tag(name:"affected", value:"'dovecot' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"dovecot", rpm:"dovecot~2.2.36.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-devel", rpm:"dovecot-devel~2.2.36.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-pigeonhole", rpm:"dovecot-pigeonhole~2.2.36.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-pigeonhole-devel", rpm:"dovecot-pigeonhole-devel~2.2.36.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-plugins-gssapi", rpm:"dovecot-plugins-gssapi~2.2.36.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-plugins-ldap", rpm:"dovecot-plugins-ldap~2.2.36.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-plugins-mysql", rpm:"dovecot-plugins-mysql~2.2.36.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-plugins-pgsql", rpm:"dovecot-plugins-pgsql~2.2.36.1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-plugins-sqlite", rpm:"dovecot-plugins-sqlite~2.2.36.1~1.mga6", rls:"MAGEIA6"))) {
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
