# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0062");
  script_cve_id("CVE-2013-4449");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0062)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0062");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0062.html");
  script_xref(name:"URL", value:"http://www.openldap.org/its/index.cgi/Incoming?id=7723");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12586");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2014-0126.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openldap' package(s) announced via the MGASA-2014-0062 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A denial of service flaw was found in the way the OpenLDAP server daemon
(slapd) performed reference counting when using the rwm (rewrite/remap)
overlay. A remote attacker able to query the OpenLDAP server could use this
flaw to crash the server by immediately unbinding from the server after
sending a search request (CVE-2013-4449).");

  script_tag(name:"affected", value:"'openldap' package(s) on Mageia 3, Mageia 4.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"lib64ldap2.4_2", rpm:"lib64ldap2.4_2~2.4.33~7.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ldap2.4_2-devel", rpm:"lib64ldap2.4_2-devel~2.4.33~7.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ldap2.4_2-static-devel", rpm:"lib64ldap2.4_2-static-devel~2.4.33~7.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap2.4_2", rpm:"libldap2.4_2~2.4.33~7.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap2.4_2-devel", rpm:"libldap2.4_2-devel~2.4.33~7.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap2.4_2-static-devel", rpm:"libldap2.4_2-static-devel~2.4.33~7.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap", rpm:"openldap~2.4.33~7.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-clients", rpm:"openldap-clients~2.4.33~7.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-doc", rpm:"openldap-doc~2.4.33~7.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-servers", rpm:"openldap-servers~2.4.33~7.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-servers-devel", rpm:"openldap-servers-devel~2.4.33~7.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-testprogs", rpm:"openldap-testprogs~2.4.33~7.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-tests", rpm:"openldap-tests~2.4.33~7.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"lib64ldap2.4_2", rpm:"lib64ldap2.4_2~2.4.38~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ldap2.4_2-devel", rpm:"lib64ldap2.4_2-devel~2.4.38~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ldap2.4_2-static-devel", rpm:"lib64ldap2.4_2-static-devel~2.4.38~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap2.4_2", rpm:"libldap2.4_2~2.4.38~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap2.4_2-devel", rpm:"libldap2.4_2-devel~2.4.38~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap2.4_2-static-devel", rpm:"libldap2.4_2-static-devel~2.4.38~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap", rpm:"openldap~2.4.38~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-back_bdb", rpm:"openldap-back_bdb~2.4.38~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-back_mdb", rpm:"openldap-back_mdb~2.4.38~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-back_sql", rpm:"openldap-back_sql~2.4.38~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-clients", rpm:"openldap-clients~2.4.38~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-doc", rpm:"openldap-doc~2.4.38~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-servers", rpm:"openldap-servers~2.4.38~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-servers-devel", rpm:"openldap-servers-devel~2.4.38~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-testprogs", rpm:"openldap-testprogs~2.4.38~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap-tests", rpm:"openldap-tests~2.4.38~1.1.mga4", rls:"MAGEIA4"))) {
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
