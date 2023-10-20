# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0007");
  script_cve_id("CVE-2016-0736", "CVE-2016-2161", "CVE-2016-8743", "CVE-2017-3167", "CVE-2017-3169", "CVE-2017-7668", "CVE-2017-7679", "CVE-2017-9788", "CVE-2017-9798");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)");

  script_name("Mageia: Security Advisory (MGASA-2018-0007)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0007");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0007.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20002");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3896");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3913");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/usn/usn-3425-1/");
  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_24.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache' package(s) announced via the MGASA-2018-0007 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"mod_sessioncrypto was encrypting its data/cookie using the configured ciphers
with possibly either CBC or ECB modes of operation (AES256-CBC by default),
hence no selectable or builtin authenticated encryption. This made it
vulnerable to padding oracle attacks, particularly with CBC (CVE-2016-0736).

Malicious input to mod_auth_digest will cause the server to crash, and each
instance continues to crash even for subsequently valid requests
(CVE-2016-2161).

Emmanuel Dreyfus reported that the use of ap_get_basic_auth_pw() by third-party
modules outside of the authentication phase may lead to authentication
requirements being bypassed (CVE-2017-3167).

Vasileios Panopoulos of AdNovum Informatik AG discovered that mod_ssl may
dereference a NULL pointer when third-party modules call
ap_hook_process_connection() during an HTTP request to an HTTPS port leading to
a denial of service (CVE-2017-3169).

Javier Jimenez reported that the HTTP strict parsing contains a flaw leading to
a buffer overread in ap_find_token(). A remote attacker can take advantage of
this flaw by carefully crafting a sequence of request headers to cause a
segmentation fault, or to force ap_find_token() to return an incorrect value
(CVE-2017-7668).

ChenQin and Hanno Boeck reported that mod_mime can read one byte past the end of
a buffer when sending a malicious Content-Type response header (CVE-2017-7679).

Robert Swiecki reported that mod_auth_digest does not properly initialize or
reset the value placeholder in [Proxy-]Authorization headers of type 'Digest'
between successive key=value assignments, leading to information disclosure or
denial of service (CVE-2017-9788).

Hanno Bock discovered that the Apache HTTP Server incorrectly handled Limit
directives in .htaccess files. In certain configurations, a remote attacker
could possibly use this issue to read arbitrary server memory, including
sensitive information. This issue is known as Optionsbleed (CVE-2017-9798).");

  script_tag(name:"affected", value:"'apache' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"apache", rpm:"apache~2.4.10~16.7.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-devel", rpm:"apache-devel~2.4.10~16.7.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-doc", rpm:"apache-doc~2.4.10~16.7.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-htcacheclean", rpm:"apache-htcacheclean~2.4.10~16.7.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_cache", rpm:"apache-mod_cache~2.4.10~16.7.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_dav", rpm:"apache-mod_dav~2.4.10~16.7.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_dbd", rpm:"apache-mod_dbd~2.4.10~16.7.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_ldap", rpm:"apache-mod_ldap~2.4.10~16.7.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_proxy", rpm:"apache-mod_proxy~2.4.10~16.7.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_proxy_html", rpm:"apache-mod_proxy_html~2.4.10~16.7.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_session", rpm:"apache-mod_session~2.4.10~16.7.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_ssl", rpm:"apache-mod_ssl~2.4.10~16.7.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_suexec", rpm:"apache-mod_suexec~2.4.10~16.7.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_userdir", rpm:"apache-mod_userdir~2.4.10~16.7.mga5", rls:"MAGEIA5"))) {
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
