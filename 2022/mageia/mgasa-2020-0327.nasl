# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0327");
  script_cve_id("CVE-2020-11984", "CVE-2020-11993", "CVE-2020-9490");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)");

  script_name("Mageia: Security Advisory (MGASA-2020-0327)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0327");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0327.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27058");
  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_24.html#2.4.44");
  script_xref(name:"URL", value:"https://downloads.apache.org/httpd/CHANGES_2.4.46");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache' package(s) announced via the MGASA-2020-0327 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Apache HTTP Server versions 2.4.20 to 2.4.43. A specially crafted value for the
'Cache-Digest' header in a HTTP/2 request would result in a crash when the
server actually tries to HTTP/2 PUSH a resource afterwards. Configuring the
HTTP/2 feature via 'H2Push off' will mitigate this vulnerability for unpatched
servers (CVE-2020-9490).

Apache HTTP server 2.4.32 to 2.4.44 mod_proxy_uwsgi info disclosure and
possible remote code execution (CVE-2020-11984).

Apache HTTP Server versions 2.4.20 to 2.4.43 When trace/debug was enabled for
the HTTP/2 module and on certain traffic edge patterns, logging statements were
made on the wrong connection, causing concurrent use of memory pools.
Configuring the LogLevel of mod_http2 above 'info' will mitigate this
vulnerability for unpatched servers (CVE-2020-11993).

The apache package has been updated to version 2.4.46, fixing these issues and
other bugs. See the upstream CHANGES file for details.");

  script_tag(name:"affected", value:"'apache' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"apache", rpm:"apache~2.4.46~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-devel", rpm:"apache-devel~2.4.46~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-doc", rpm:"apache-doc~2.4.46~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-htcacheclean", rpm:"apache-htcacheclean~2.4.46~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_brotli", rpm:"apache-mod_brotli~2.4.46~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_cache", rpm:"apache-mod_cache~2.4.46~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_dav", rpm:"apache-mod_dav~2.4.46~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_dbd", rpm:"apache-mod_dbd~2.4.46~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_http2", rpm:"apache-mod_http2~2.4.46~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_ldap", rpm:"apache-mod_ldap~2.4.46~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_proxy", rpm:"apache-mod_proxy~2.4.46~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_proxy_html", rpm:"apache-mod_proxy_html~2.4.46~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_session", rpm:"apache-mod_session~2.4.46~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_ssl", rpm:"apache-mod_ssl~2.4.46~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_suexec", rpm:"apache-mod_suexec~2.4.46~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_userdir", rpm:"apache-mod_userdir~2.4.46~1.mga7", rls:"MAGEIA7"))) {
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
