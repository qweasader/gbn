# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0431");
  script_cve_id("CVE-2020-25713");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-20 20:15:34 +0000 (Thu, 20 May 2021)");

  script_name("Mageia: Security Advisory (MGASA-2020-0431)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0431");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0431.html");
  script_xref(name:"URL", value:"https://bugs.librdf.org/mantis/view.php?id=650");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27605");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2020/11/13/1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2020/11/16/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'raptor2' package(s) announced via the MGASA-2020-0431 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A malformed input file can lead to a segfault due to an out of bounds array
access in raptor_xml_writer_start_element_common. (CVE-2020-25713)");

  script_tag(name:"affected", value:"'raptor2' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64raptor2-devel", rpm:"lib64raptor2-devel~2.0.15~11.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64raptor2_0", rpm:"lib64raptor2_0~2.0.15~11.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraptor2-devel", rpm:"libraptor2-devel~2.0.15~11.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libraptor2_0", rpm:"libraptor2_0~2.0.15~11.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"raptor2", rpm:"raptor2~2.0.15~11.1.mga7", rls:"MAGEIA7"))) {
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
