# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0001");
  script_cve_id("CVE-2016-9909", "CVE-2016-9910");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-23 18:56:00 +0000 (Thu, 23 Feb 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0001)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0001");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0001.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19912");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/12/08/8");
  script_xref(name:"URL", value:"https://github.com/html5lib/html5lib-python/issues/11");
  script_xref(name:"URL", value:"https://github.com/html5lib/html5lib-python/issues/12");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-html5lib' package(s) announced via the MGASA-2017-0001 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Fixes a potential cross-site scripting vulnerability: quote attributes
that need escaping in legacy browsers. (CVE-2016-9909, CVE-2016-9910)");

  script_tag(name:"affected", value:"'python-html5lib' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-html5lib", rpm:"python-html5lib~1.0b3~7.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-html5lib", rpm:"python3-html5lib~1.0b3~7.1.mga5", rls:"MAGEIA5"))) {
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
