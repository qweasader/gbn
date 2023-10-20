# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0284");
  script_cve_id("CVE-2013-1443", "CVE-2013-4315");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2013-0284)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0284");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0284.html");
  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2013/sep/10/security-releases-issued/");
  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2013/sep/15/security/");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2755");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11217.mga3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django' package(s) announced via the MGASA-2013-0284 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated python-django package fixes security vulnerabilities:

Rainer Koirikivi discovered a directory traversal vulnerability with 'ssi'
template tags in python-django, a high-level Python web development framework.
It was shown that the handling of the 'ALLOWED_INCLUDE_ROOTS' setting, used to
represent allowed prefixes for the {% ssi %} template tag, is vulnerable to a
directory traversal attack, by specifying a file path which begins as the
absolute path of a directory in 'ALLOWED_INCLUDE_ROOTS', and then uses relative
paths to break free. To exploit this vulnerability an attacker must be in a
position to alter templates on the site, or the site to be attacked must have
one or more templates making use of the 'ssi' tag, and must allow some form of
unsanitized user input to be used as an argument to the 'ssi' tag
(CVE-2013-4315).

Django before 1.4.8 allows for denial-of-service attacks through repeated
submission of large passwords, tying up server resources in the expensive
computation of the corresponding hashes (CVE-2013-1443).");

  script_tag(name:"affected", value:"'python-django' package(s) on Mageia 3.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-django", rpm:"python-django~1.4.8~1.mga3", rls:"MAGEIA3"))) {
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
