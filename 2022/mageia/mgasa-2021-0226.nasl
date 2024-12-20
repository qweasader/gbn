# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0226");
  script_cve_id("CVE-2021-3405");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-01 14:14:14 +0000 (Mon, 01 Mar 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0226)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0226");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0226.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28278");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/7COLX6WFFOI3RIOY2IOXWASU3QKAOWKO/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/JNHQI6MDOECJ2HT5GCLEX2DMJFEOWPW7/");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2629");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libebml, libmatroska, mkvtoolnix' package(s) announced via the MGASA-2021-0226 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated libebml packages fix security vulnerabilities:

Heap use-after-free when parsing malformed file.

A flaw was found in libebml before 1.4.2. A heap overflow bug exists in the implementation of EbmlString::ReadData and EbmlUnicodeString::ReadData in libebml (CVE-2021-3405).

The mkvtoolnix, libmatroska packages have been rebuilt for the
updated libebml.");

  script_tag(name:"affected", value:"'libebml, libmatroska, mkvtoolnix' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64ebml-devel", rpm:"lib64ebml-devel~1.4.2~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ebml5", rpm:"lib64ebml5~1.4.2~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64matroska-devel", rpm:"lib64matroska-devel~1.5.0~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64matroska6", rpm:"lib64matroska6~1.5.0~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebml", rpm:"libebml~1.4.2~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebml-devel", rpm:"libebml-devel~1.4.2~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libebml5", rpm:"libebml5~1.4.2~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmatroska", rpm:"libmatroska~1.5.0~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmatroska-devel", rpm:"libmatroska-devel~1.5.0~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmatroska6", rpm:"libmatroska6~1.5.0~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mkvtoolnix", rpm:"mkvtoolnix~32.0.0~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mkvtoolnix-gui", rpm:"mkvtoolnix-gui~32.0.0~2.1.mga7", rls:"MAGEIA7"))) {
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
