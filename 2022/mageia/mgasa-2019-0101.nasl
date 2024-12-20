# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0101");
  script_cve_id("CVE-2019-7663");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-15 15:05:49 +0000 (Fri, 15 Feb 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0101)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0101");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0101.html");
  script_xref(name:"URL", value:"http://bugzilla.maptools.org/show_bug.cgi?id=2831");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24393");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/QLLVSXFUKP2QSOFI6RRTYD737HBS7UGT/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libtiff' package(s) announced via the MGASA-2019-0101 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An Invalid Address dereference was discovered in
TIFFWriteDirectoryTagTransferfunction in libtiff/tif_dirwrite.c in LibTIFF
4.0.10, affecting the cpSeparateBufToContigBuf function in tiffcp.c.
Remote attackers could leverage this vulnerability to cause a
denial-of-service via a crafted tiff file. This is different from
CVE-2018-12900. (CVE-2019-7663)

The invertImage() function in tiffcrop.c:9206 allows remote attackers to
cause a denial of service (heap buffer overflow) via invert color space.");

  script_tag(name:"affected", value:"'libtiff' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"lib64tiff-devel", rpm:"lib64tiff-devel~4.0.10~1.git20190219.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tiff-static-devel", rpm:"lib64tiff-static-devel~4.0.10~1.git20190219.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tiff5", rpm:"lib64tiff5~4.0.10~1.git20190219.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~4.0.10~1.git20190219.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~4.0.10~1.git20190219.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-progs", rpm:"libtiff-progs~4.0.10~1.git20190219.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff-static-devel", rpm:"libtiff-static-devel~4.0.10~1.git20190219.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5", rpm:"libtiff5~4.0.10~1.git20190219.1.mga6", rls:"MAGEIA6"))) {
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
