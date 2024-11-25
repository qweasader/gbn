# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0166");
  script_cve_id("CVE-2018-7536", "CVE-2018-7537");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-26 17:25:42 +0000 (Mon, 26 Mar 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0166)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0166");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0166.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22727");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/CVE-2018-7536");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/CVE-2018-7537");
  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2018/mar/06/security-releases/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django' package(s) announced via the MGASA-2018-0166 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The python-django package has been updated to fix 2 security issues.


CVE-2018-7536: Denial-of-service possibility in urlize and urlizetrunc template
filters.

CVE-2018-7537: Denial-of-service possibility in truncatechars_html and
truncatewords_html template filters.");

  script_tag(name:"affected", value:"'python-django' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-django", rpm:"python-django~1.8.19~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-django-bash-completion", rpm:"python-django-bash-completion~1.8.19~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-django-doc", rpm:"python-django-doc~1.8.19~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-django", rpm:"python3-django~1.8.19~1.mga6", rls:"MAGEIA6"))) {
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
