# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0044");
  script_cve_id("CVE-2018-11254", "CVE-2018-11255", "CVE-2018-11256", "CVE-2018-12982", "CVE-2018-14320", "CVE-2018-19532", "CVE-2018-5295", "CVE-2018-5296", "CVE-2018-5308", "CVE-2018-5309", "CVE-2018-5783", "CVE-2018-8001");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-19 14:54:29 +0000 (Wed, 19 Dec 2018)");

  script_name("Mageia: Security Advisory (MGASA-2019-0044)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0044");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0044.html");
  script_xref(name:"URL", value:"http://lists.suse.com/pipermail/sle-security-updates/2018-August/004491.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21511");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/2U7MKKI2OP43FRIS44DJXIJYDWTNAWQ6/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/QYCCO7ZOZI6KUCLH6IZ5XS5LDANULNR4/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2019-01/msg00066.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'podofo' package(s) announced via the MGASA-2019-0044 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The podofo package has been updated to fix several security issues.");

  script_tag(name:"affected", value:"'podofo' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64podofo-devel", rpm:"lib64podofo-devel~0.9.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64podofo0.9.6", rpm:"lib64podofo0.9.6~0.9.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpodofo-devel", rpm:"libpodofo-devel~0.9.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpodofo0.9.6", rpm:"libpodofo0.9.6~0.9.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podofo", rpm:"podofo~0.9.6~1.mga6", rls:"MAGEIA6"))) {
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
