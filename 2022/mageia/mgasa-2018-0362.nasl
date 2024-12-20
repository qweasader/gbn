# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0362");
  script_cve_id("CVE-2018-1002209");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-25 17:29:02 +0000 (Wed, 25 Jul 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0362)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0362");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0362.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23446");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/TMQZPZKZJRQ6ESHXO5LCLIBYWOJX4HAX/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'quazip' package(s) announced via the MGASA-2018-0362 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated quazip packages fix security vulnerability:

A vulnerability has been found in the way developers have implemented the
archive extraction of files. An arbitrary file write vulnerability, that
can be achieved using a specially crafted zip archive (affects other
archives as well, bzip2, tar,xz, war, cpio, 7z), that holds path traversal
filenames. So when the filename gets concatenated to the target extraction
directory, the final path ends up outside of the target folder. Of course
if an executable or a configuration file is overwritten with a file
containing malicious code, the problem can turn into an arbitrary code
execution issue quite easily. This affects multiple libraries that lacks of
a high level APIs that provide the archive extraction functionality
(CVE-2018-1002209).");

  script_tag(name:"affected", value:"'quazip' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64quazip-devel", rpm:"lib64quazip-devel~0.7.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64quazip-qt4-devel", rpm:"lib64quazip-qt4-devel~0.7.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64quazip1", rpm:"lib64quazip1~0.7.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64quazip5_1", rpm:"lib64quazip5_1~0.7.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquazip-devel", rpm:"libquazip-devel~0.7.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquazip-qt4-devel", rpm:"libquazip-qt4-devel~0.7.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquazip1", rpm:"libquazip1~0.7.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquazip5_1", rpm:"libquazip5_1~0.7.6~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"quazip", rpm:"quazip~0.7.6~1.mga6", rls:"MAGEIA6"))) {
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
