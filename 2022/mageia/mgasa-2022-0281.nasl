# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0281");
  script_cve_id("CVE-2022-34265", "CVE-2022-36359");
  script_tag(name:"creation_date", value:"2022-08-15 07:04:54 +0000 (Mon, 15 Aug 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-13 15:39:00 +0000 (Wed, 13 Jul 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0281)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0281");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0281.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30603");
  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2022/aug/03/security-releases/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django' package(s) announced via the MGASA-2022-0281 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in Django 3.2 before 3.2.14 and 4.0 before 4.0.6.
The Trunc() and Extract() database functions are subject to SQL injection
if untrusted data is used as a kind/lookup_name value. Applications that
constrain the lookup name and kind choice to a known safe list are
unaffected. (CVE-2022-34265)
An issue was discovered in the HTTP FileResponse class in Django 3.2
before 3.2.15 and 4.0 before 4.0.7. An application is vulnerable to a
reflected file download (RFD) attack that sets the Content-Disposition
header of a FileResponse when the filename is derived from user-supplied
input. (CVE-2022-36359)");

  script_tag(name:"affected", value:"'python-django' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"python-django", rpm:"python-django~3.2.15~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-django", rpm:"python3-django~3.2.15~1.mga8", rls:"MAGEIA8"))) {
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
