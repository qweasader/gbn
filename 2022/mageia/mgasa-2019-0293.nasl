# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0293");
  script_cve_id("CVE-2019-10018", "CVE-2019-10019", "CVE-2019-10021", "CVE-2019-10023", "CVE-2019-16927");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-01 17:02:00 +0000 (Tue, 01 Oct 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0293)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0293");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0293.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25364");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xpdf' package(s) announced via the MGASA-2019-0293 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated xpdf packages fix security vulnerabilities:

An issue was discovered in Xpdf 4.01.01. There is an FPE in the function
PostScriptFunction::exec at Function.cc for the psOpIdiv case.
(CVE-2019-10018)

An issue was discovered in Xpdf 4.01.01. There is an FPE in the function
PSOutputDev::checkPageSlice at PSOutputDev.cc for nStripes.
(CVE-2019-10019)

An issue was discovered in Xpdf 4.01.01. There is an FPE in the function
ImageStream::ImageStream at Stream.cc for nComps. (CVE-2019-10021)

An issue was discovered in Xpdf 4.01.01. There is an FPE in the function
PostScriptFunction::exec at Function.cc for the psOpMod case.
(CVE-2019-10023)

Xpdf 4.01.01 has an out-of-bounds write in the vertProfile part of the
TextPage::findGaps function in TextOutputDev.cc, a different vulnerability
than CVE-2019-9877. (CVE-2019-16927)");

  script_tag(name:"affected", value:"'xpdf' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"xpdf", rpm:"xpdf~4.02~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xpdf-common", rpm:"xpdf-common~4.02~1.mga7", rls:"MAGEIA7"))) {
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
