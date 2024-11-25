# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0380");
  script_cve_id("CVE-2020-14002");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-07 13:19:39 +0000 (Tue, 07 Jul 2020)");

  script_name("Mageia: Security Advisory (MGASA-2021-0380)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0380");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0380.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29186");
  script_xref(name:"URL", value:"https://filezilla-project.org/versions.php");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/26TACCSQYYCPWAJYNAUIXJGZ5RGORJZV/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/IRAC73KPNR4HKTRKJNLIZXCYIP6STUZN/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/IRKUHQP6O6TGN64SI7PYCKHJT24Y2EY2/");
  script_xref(name:"URL", value:"https://www.chiark.greenend.org.uk/~sgtatham/putty/changes.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'filezilla, libfilezilla' package(s) announced via the MGASA-2021-0380 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"filezilla embeds a PuTTY client that was vulnerable:
PuTTY 0.68 through 0.73 has an Observable Discrepancy leading to an
information leak in the algorithm negotiation. This allows man-in-the-middle
attackers to target initial connection attempts (where no host key for the
server has been cached by the client) (CVE-2020-14002).

The filezilla packages are updated to fix this issue to 3.55.0 version among
other bugfixes since 3.51.0 we shipped in Mageia 8. See upstream release notes
for more information.");

  script_tag(name:"affected", value:"'filezilla, libfilezilla' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"filezilla", rpm:"filezilla~3.55.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64filezilla-devel", rpm:"lib64filezilla-devel~0.30.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64filezilla15", rpm:"lib64filezilla15~0.30.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfilezilla", rpm:"libfilezilla~0.30.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfilezilla-devel", rpm:"libfilezilla-devel~0.30.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfilezilla-i18n", rpm:"libfilezilla-i18n~0.30.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfilezilla15", rpm:"libfilezilla15~0.30.0~1.mga8", rls:"MAGEIA8"))) {
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
