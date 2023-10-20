# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0045");
  script_cve_id("CVE-2018-10536", "CVE-2018-10537", "CVE-2018-10538", "CVE-2018-10539", "CVE-2018-10540", "CVE-2018-19840", "CVE-2018-19841", "CVE-2018-6767", "CVE-2018-7253", "CVE-2018-7254");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-20 10:15:00 +0000 (Fri, 20 Dec 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0045)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0045");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0045.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22588");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/3568-1/");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/3578-1/");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/3637-1/");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/3839-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wavpack' package(s) announced via the MGASA-2019-0045 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Joonun Jang discovered that WavPack incorrectly handled certain RF64
files. An attacker could possibly use this to cause a denial of service
(CVE-2018-6767).

It was discovered that WavPack incorrectly handled certain DSDIFF files.
An attacker could possibly use this to execute arbitrary code or cause a
denial of service (CVE-2018-7253).

It was discovered that WavPack incorrectly handled certain CAF files. An
attacker could possibly use this to cause a denial of service
(CVE-2018-7254).

Thuan Pham, Marcel Bohme, Andrew Santosa and Alexandru Razvan Caciulescu
discovered that WavPack incorrectly handled certain .wav files. An
attacker could possibly use this to execute arbitrary code or cause a
denial of service (CVE-2018-10536, CVE-2018-10537).

Thuan Pham, Marcel Bohme, Andrew Santosa and Alexandru Razvan Caciulescu
discovered that WavPack incorrectly handled certain .wav files. An
attacker could possibly use this to cause a denial of service
(CVE-2018-10538, CVE-2018-10539, CVE-2018-10540).

It was discovered that WavPack incorrectly handled certain WAV files. An
attacker could possibly use this issue to cause a denial of service
(CVE-2018-19840, CVE-2018-19841).");

  script_tag(name:"affected", value:"'wavpack' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64wavpack-devel", rpm:"lib64wavpack-devel~5.1.0~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wavpack1", rpm:"lib64wavpack1~5.1.0~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwavpack-devel", rpm:"libwavpack-devel~5.1.0~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwavpack1", rpm:"libwavpack1~5.1.0~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wavpack", rpm:"wavpack~5.1.0~1.1.mga6", rls:"MAGEIA6"))) {
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
