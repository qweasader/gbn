# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0326");
  script_cve_id("CVE-2017-14406", "CVE-2017-14407", "CVE-2017-14408", "CVE-2017-14409", "CVE-2017-14410", "CVE-2017-14411", "CVE-2017-14412", "CVE-2018-10777");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-12 17:53:00 +0000 (Tue, 12 Jun 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0326)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0326");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0326.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21706");
  script_xref(name:"URL", value:"https://sourceforge.net/p/mp3gain/bugs/40/");
  script_xref(name:"URL", value:"https://sourceforge.net/p/mp3gain/bugs/41/");
  script_xref(name:"URL", value:"https://sourceforge.net/p/mp3gain/bugs/43/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mp3gain' package(s) announced via the MGASA-2018-0326 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A NULL pointer dereference was discovered in sync_buffer in interface.c
in mpglibDBL, as used in MP3Gain version 1.5.2. The vulnerability causes
a segmentation fault and application crash, which leads to remote denial
of service (CVE-2017-14406).

A stack-based buffer over-read was discovered in filterYule in
gain_analysis.c in MP3Gain version 1.5.2. The vulnerability causes an
application crash, which leads to remote denial of service (CVE-2017-14407).

A stack-based buffer over-read was discovered in dct36 in layer3.c in
mpglibDBL, as used in MP3Gain version 1.5.2. The vulnerability causes an
application crash, which leads to remote denial of service (CVE-2017-14408).

A buffer overflow was discovered in III_dequantize_sample in layer3.c in
mpglibDBL, as used in MP3Gain version 1.5.2. The vulnerability causes an
out-of-bounds write, which leads to remote denial of service or possibly
code execution (CVE-2017-14409).

A buffer over-read was discovered in III_i_stereo in layer3.c in mpglibDBL,
as used in MP3Gain version 1.5.2. The vulnerability causes an application
crash, which leads to remote denial of service (CVE-2017-14410).

A stack-based buffer overflow was discovered in copy_mp in interface.c in
mpglibDBL, as used in MP3Gain version 1.5.2. The vulnerability causes an
out-of-bounds write, which leads to remote denial of service or possibly
code execution (CVE-2017-14411).

An invalid memory write was discovered in copy_mp in interface.c in
mpglibDBL, as used in MP3Gain version 1.5.2. The vulnerability causes a
denial of service (segmentation fault and application crash) or possibly
unspecified other impact (CVE-2017-14412).

Buffer overflow in the WriteMP3GainAPETag function in apetag.c in mp3gain
through 1.5.2-r2 allows remote attackers to cause a denial of service
(application crash) or possibly have unspecified other impact
(CVE-2018-10777).");

  script_tag(name:"affected", value:"'mp3gain' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"mp3gain", rpm:"mp3gain~1.6.2~1.mga6", rls:"MAGEIA6"))) {
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
