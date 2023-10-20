# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0179");
  script_cve_id("CVE-2015-3143", "CVE-2015-3145", "CVE-2015-3148");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0179)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0179");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0179.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15746");
  script_xref(name:"URL", value:"http://curl.haxx.se/docs/adv_20150422A.html");
  script_xref(name:"URL", value:"http://curl.haxx.se/docs/adv_20150422D.html");
  script_xref(name:"URL", value:"http://curl.haxx.se/docs/adv_20150422B.html");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3232");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the MGASA-2015-0179 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated curl packages fix security vulnerabilities:

NTLM-authenticated connections could be wrongly reused for requests without
any credentials set, leading to HTTP requests being sent over the connection
authenticated as a different user (CVE-2015-3143).

When parsing HTTP cookies, if the parsed cookie's 'path' element consists of a
single double-quote, libcurl would try to write to an invalid heap memory
address. This could allow remote attackers to cause a denial of service
(crash) (CVE-2015-3145).

When doing HTTP requests using the Negotiate authentication method along with
NTLM, the connection used would not be marked as authenticated, making it
possible to reuse it and send requests for one user over the connection
authenticated as a different user (CVE-2015-3148).");

  script_tag(name:"affected", value:"'curl' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.34.0~1.6.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"curl-examples", rpm:"curl-examples~7.34.0~1.6.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64curl-devel", rpm:"lib64curl-devel~7.34.0~1.6.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64curl4", rpm:"lib64curl4~7.34.0~1.6.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl-devel", rpm:"libcurl-devel~7.34.0~1.6.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4", rpm:"libcurl4~7.34.0~1.6.mga4", rls:"MAGEIA4"))) {
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
