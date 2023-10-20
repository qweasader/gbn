# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0084");
  script_cve_id("CVE-2017-14632", "CVE-2017-14633");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-07 20:26:00 +0000 (Mon, 07 Dec 2020)");

  script_name("Mageia: Security Advisory (MGASA-2018-0084)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0084");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0084.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22378");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2018-01/msg00015.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvorbis' package(s) announced via the MGASA-2018-0084 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Xiph.Org libvorbis 1.3.5 allows Remote Code Execution upon freeing
uninitialized memory in the function vorbis_analysis_headerout() in
info.c when vi->channels<=0, a similar issue to Mozilla bug 550184
(CVE-2017-14632).

In Xiph.Org libvorbis 1.3.5, an out-of-bounds array read vulnerability
exists in the function mapping0_forward() in mapping0.c, which may lead
to DoS when operating on a crafted audio file with vorbis_analysis()
(CVE-2017-14633).");

  script_tag(name:"affected", value:"'libvorbis' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64vorbis-devel", rpm:"lib64vorbis-devel~1.3.5~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vorbis0", rpm:"lib64vorbis0~1.3.5~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vorbisenc2", rpm:"lib64vorbisenc2~1.3.5~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vorbisfile3", rpm:"lib64vorbisfile3~1.3.5~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbis", rpm:"libvorbis~1.3.5~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbis-devel", rpm:"libvorbis-devel~1.3.5~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbis0", rpm:"libvorbis0~1.3.5~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbisenc2", rpm:"libvorbisenc2~1.3.5~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvorbisfile3", rpm:"libvorbisfile3~1.3.5~1.1.mga5", rls:"MAGEIA5"))) {
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
