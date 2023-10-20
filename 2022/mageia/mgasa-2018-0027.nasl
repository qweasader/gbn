# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0027");
  script_cve_id("CVE-2016-10254", "CVE-2016-10255", "CVE-2017-7607", "CVE-2017-7608", "CVE-2017-7609", "CVE-2017-7610", "CVE-2017-7611", "CVE-2017-7612", "CVE-2017-7613");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-20 03:15:00 +0000 (Thu, 20 Jun 2019)");

  script_name("Mageia: Security Advisory (MGASA-2018-0027)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0027");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0027.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20557");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/03/22/2");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/03/22/1");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/04/10/8");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/04/10/9");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/04/10/11");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/04/10/12");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/04/10/13");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/04/10/14");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/04/10/15");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'elfutils' package(s) announced via the MGASA-2018-0027 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The elfutils package has been updated to version 0.169 to fix several bugs
that can lead to memory allocation failures or heap overflows
(CVE-2016-10254, CVE-2016-10255, CVE-2017-7607, CVE-2017-7608,
CVE-2017-7609, CVE-2017-7610, CVE-2017-7611, CVE-2017-7612,
CVE-2017-7613).");

  script_tag(name:"affected", value:"'elfutils' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"elfutils", rpm:"elfutils~0.169~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64elfutils-devel", rpm:"lib64elfutils-devel~0.169~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64elfutils-static-devel", rpm:"lib64elfutils-static-devel~0.169~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64elfutils1", rpm:"lib64elfutils1~0.169~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelfutils-devel", rpm:"libelfutils-devel~0.169~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelfutils-static-devel", rpm:"libelfutils-static-devel~0.169~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libelfutils1", rpm:"libelfutils1~0.169~1.mga5", rls:"MAGEIA5"))) {
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
