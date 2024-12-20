# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0387");
  script_cve_id("CVE-2021-36740");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-05 15:02:08 +0000 (Thu, 05 Aug 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0387)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0387");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0387.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29290");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/THV2DQA2GS65HUCKK4KSD2XLN3AAQ2V5/");
  script_xref(name:"URL", value:"https://varnish-cache.org/security/VSV00007.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'varnish' package(s) announced via the MGASA-2021-0387 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Varnish Cache, with HTTP/2 enabled, allows request smuggling and VCL
authorization bypass via a large Content-Length header for a POST request.
This affects Varnish Enterprise 6.0.x before 6.0.8r3, and Varnish Cache 5.x
and 6.x before 6.5.2, 6.6.x before 6.6.1, and 6.0 LTS before 6.0.8
(CVE-2021-36740).");

  script_tag(name:"affected", value:"'varnish' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64varnish-devel", rpm:"lib64varnish-devel~6.5.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64varnish2", rpm:"lib64varnish2~6.5.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvarnish-devel", rpm:"libvarnish-devel~6.5.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvarnish2", rpm:"libvarnish2~6.5.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"varnish", rpm:"varnish~6.5.1~1.1.mga8", rls:"MAGEIA8"))) {
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
