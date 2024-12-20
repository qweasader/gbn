# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0016");
  script_cve_id("CVE-2017-17554", "CVE-2018-14522", "CVE-2018-14523");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-15 14:30:22 +0000 (Sat, 15 Sep 2018)");

  script_name("Mageia: Security Advisory (MGASA-2019-0016)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0016");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0016.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23211");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2018-08/msg00089.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'aubio' package(s) announced via the MGASA-2019-0016 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"NULL pointer dereference in the function aubio_source_avcodec_readframe
which may lead to DoS when playing a crafted audio file (CVE-2017-17554).

A crash in aubio_pitch_set_unit (CVE-2018-14522).

A buffer overrread resulting in crash or information leakage in
new_aubio_pitchyinfft (CVE-2018-14523).");

  script_tag(name:"affected", value:"'aubio' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"aubio", rpm:"aubio~0.4.2~2.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64aubio-devel", rpm:"lib64aubio-devel~0.4.2~2.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64aubio4", rpm:"lib64aubio4~0.4.2~2.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaubio-devel", rpm:"libaubio-devel~0.4.2~2.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaubio4", rpm:"libaubio4~0.4.2~2.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-aubio", rpm:"python-aubio~0.4.2~2.2.mga6", rls:"MAGEIA6"))) {
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
