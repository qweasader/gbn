# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0305");
  script_cve_id("CVE-2014-0117", "CVE-2014-0118", "CVE-2014-0226", "CVE-2014-0231");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0305)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0305");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0305.html");
  script_xref(name:"URL", value:"http://httpd.apache.org/security/vulnerabilities_24.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13788");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2014-0921.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache' package(s) announced via the MGASA-2014-0305 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A race condition flaw, leading to heap-based buffer overflows, was found in
the mod_status httpd module. A remote attacker able to access a status page
served by mod_status on a server using a threaded Multi-Processing Module
(MPM) could send a specially crafted request that would cause the httpd
child process to crash or, possibly, allow the attacker to execute
arbitrary code with the privileges of the 'apache' user (CVE-2014-0226).

A denial of service flaw was found in the mod_proxy httpd module. A remote
attacker could send a specially crafted request to a server configured as a
reverse proxy using a threaded Multi-Processing Modules (MPM) that would
cause the httpd child process to crash (CVE-2014-0117).

A denial of service flaw was found in the way httpd's mod_deflate module
handled request body decompression (configured via the 'DEFLATE' input
filter). A remote attacker able to send a request whose body would be
decompressed could use this flaw to consume an excessive amount of system
memory and CPU on the target system (CVE-2014-0118).

A denial of service flaw was found in the way httpd's mod_cgid module
executed CGI scripts that did not read data from the standard input.
A remote attacker could submit a specially crafted request that would cause
the httpd child process to hang indefinitely (CVE-2014-0231).");

  script_tag(name:"affected", value:"'apache' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"apache", rpm:"apache~2.4.7~5.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-devel", rpm:"apache-devel~2.4.7~5.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-doc", rpm:"apache-doc~2.4.7~5.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-htcacheclean", rpm:"apache-htcacheclean~2.4.7~5.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_cache", rpm:"apache-mod_cache~2.4.7~5.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_dav", rpm:"apache-mod_dav~2.4.7~5.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_dbd", rpm:"apache-mod_dbd~2.4.7~5.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_ldap", rpm:"apache-mod_ldap~2.4.7~5.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_proxy", rpm:"apache-mod_proxy~2.4.7~5.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_proxy_html", rpm:"apache-mod_proxy_html~2.4.7~5.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_session", rpm:"apache-mod_session~2.4.7~5.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_ssl", rpm:"apache-mod_ssl~2.4.7~5.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_suexec", rpm:"apache-mod_suexec~2.4.7~5.3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_userdir", rpm:"apache-mod_userdir~2.4.7~5.3.mga4", rls:"MAGEIA4"))) {
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
