# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0453");
  script_cve_id("CVE-2022-36227");
  script_tag(name:"creation_date", value:"2022-12-14 04:11:58 +0000 (Wed, 14 Dec 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-28 14:23:23 +0000 (Mon, 28 Nov 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0453)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0453");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0453.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31179");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/N4XUJQ5ZT6HWNXMENJI7BA5SJHZCQSOO/");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-November/013094.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libarchive' package(s) announced via the MGASA-2022-0453 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In libarchive 3.6.1, the software does not check for an error after
calling calloc function that can return with a NULL pointer if the
function fails, which leads to a resultant NULL pointer dereference.
(CVE-2022-36227)");

  script_tag(name:"affected", value:"'libarchive' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"bsdcat", rpm:"bsdcat~3.6.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bsdcpio", rpm:"bsdcpio~3.6.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bsdtar", rpm:"bsdtar~3.6.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64archive-devel", rpm:"lib64archive-devel~3.6.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64archive13", rpm:"lib64archive13~3.6.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive", rpm:"libarchive~3.6.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive-devel", rpm:"libarchive-devel~3.6.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive13", rpm:"libarchive13~3.6.1~1.1.mga8", rls:"MAGEIA8"))) {
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
