# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0536");
  script_cve_id("CVE-2014-5353");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0536)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0536");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0536.html");
  script_xref(name:"URL", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=773226");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14816");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5' package(s) announced via the MGASA-2014-0536 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated krb5 packages fix security vulnerability:

In MIT krb5, when kadmind is configured to use LDAP for the KDC
database, an authenticated remote attacker can cause a NULL dereference
by attempting to use a named ticket policy object as a password policy
for a principal. The attacker needs to be authenticated as a user who
has the elevated privilege for setting password policy by adding or
modifying principals (CVE-2014-5353).");

  script_tag(name:"affected", value:"'krb5' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.11.4~1.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-pkinit-openssl", rpm:"krb5-pkinit-openssl~1.11.4~1.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.11.4~1.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server-ldap", rpm:"krb5-server-ldap~1.11.4~1.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.11.4~1.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64krb53", rpm:"lib64krb53~1.11.4~1.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64krb53-devel", rpm:"lib64krb53-devel~1.11.4~1.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrb53", rpm:"libkrb53~1.11.4~1.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libkrb53-devel", rpm:"libkrb53-devel~1.11.4~1.3.mga4", rls:"MAGEIA4"))) {
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
