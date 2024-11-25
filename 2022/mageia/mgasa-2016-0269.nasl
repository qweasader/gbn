# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0269");
  script_cve_id("CVE-2015-8948", "CVE-2016-6261", "CVE-2016-6262", "CVE-2016-6263");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-09-08 14:19:36 +0000 (Thu, 08 Sep 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0269)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0269");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0269.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/07/21/4");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19011");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/EQDCSQNM5LICMOIEU5H63QDQ4Z436KC5/");
  script_xref(name:"URL", value:"https://lists.gnu.org/archive/html/help-libidn/2016-07/msg00009.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libidn' package(s) announced via the MGASA-2016-0269 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Out-of-bounds stack read in libidn before 1.33 in idna_to_ascii_4i
(CVE-2016-6261).

Out-of-bounds-read in libidn when reading one zero byte as input
(CVE-2015-8948, CVE-2016-6262).

In libidn before 1.33, stringprep_utf8_nfkc_normalize would crash when
presented with invalid UTF-8 (CVE-2016-6263).");

  script_tag(name:"affected", value:"'libidn' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"idn", rpm:"idn~1.33~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64idn-devel", rpm:"lib64idn-devel~1.33~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64idn11", rpm:"lib64idn11~1.33~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64idn11-java", rpm:"lib64idn11-java~1.33~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64idn11-mono", rpm:"lib64idn11-mono~1.33~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libidn", rpm:"libidn~1.33~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libidn-devel", rpm:"libidn-devel~1.33~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libidn11", rpm:"libidn11~1.33~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libidn11-java", rpm:"libidn11-java~1.33~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libidn11-mono", rpm:"libidn11-mono~1.33~1.mga5", rls:"MAGEIA5"))) {
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
