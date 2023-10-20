# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0250");
  script_cve_id("CVE-2017-1000494");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-30 20:29:00 +0000 (Thu, 30 May 2019)");

  script_name("Mageia: Security Advisory (MGASA-2018-0250)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0250");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0250.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22560");
  script_xref(name:"URL", value:"https://people.canonical.com/~ubuntu-security/cve/2017/CVE-2017-1000494.html");
  script_xref(name:"URL", value:"https://github.com/miniupnp/miniupnp/issues/268");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'miniupnpc' package(s) announced via the MGASA-2018-0250 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that miniupnpc contained a heap buffer overflow in
parseelt (minixml.c - no CVE assigned).

It was discovered that miniupnpc also contained a memory corruption
(invalid read, SIGSEGV) in NameValueParserEndElt (upnpreplyparse.c)
while handling two consecutive malformed SOAP requests
(CVE-2017-1000494).");

  script_tag(name:"affected", value:"'miniupnpc' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64miniupnpc-devel", rpm:"lib64miniupnpc-devel~2.0.20170509~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64miniupnpc16", rpm:"lib64miniupnpc16~2.0.20170509~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libminiupnpc-devel", rpm:"libminiupnpc-devel~2.0.20170509~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libminiupnpc16", rpm:"libminiupnpc16~2.0.20170509~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"miniupnpc", rpm:"miniupnpc~2.0.20170509~1.1.mga6", rls:"MAGEIA6"))) {
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
