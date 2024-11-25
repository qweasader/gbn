# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0074");
  script_cve_id("CVE-2019-1000019", "CVE-2019-1000020");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-06 16:16:10 +0000 (Wed, 06 Feb 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0074)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0074");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0074.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24337");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/3884-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libarchive' package(s) announced via the MGASA-2019-0074 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libarchive contains an out-of-bounds read vulnerability in 7zip
decompression, archive_read_support_format_7zip.c, header_bytes() that can
result in a crash (denial of service). This attack appears to be
exploitable via the victim opening a specially crafted 7zip file
(CVE-2019-1000019).

libarchive contains an infinite loop vulnerability in the ISO9660 parser,
archive_read_support_format_iso9660.c, read_CE()/parse_rockridge() that
can result in DoS by infinite loop. This attack appears to be exploitable
via the victim opening a specially crafted ISO9660 file (CVE-2019-1000020).");

  script_tag(name:"affected", value:"'libarchive' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"bsdcat", rpm:"bsdcat~3.3.1~1.5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bsdcpio", rpm:"bsdcpio~3.3.1~1.5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bsdtar", rpm:"bsdtar~3.3.1~1.5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64archive-devel", rpm:"lib64archive-devel~3.3.1~1.5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64archive13", rpm:"lib64archive13~3.3.1~1.5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive", rpm:"libarchive~3.3.1~1.5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive-devel", rpm:"libarchive-devel~3.3.1~1.5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive13", rpm:"libarchive13~3.3.1~1.5.mga6", rls:"MAGEIA6"))) {
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
