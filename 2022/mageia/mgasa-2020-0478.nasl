# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0478");
  script_cve_id("CVE-2020-27841", "CVE-2020-27842", "CVE-2020-27843", "CVE-2020-27845");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-08 18:10:17 +0000 (Fri, 08 Jan 2021)");

  script_name("Mageia: Security Advisory (MGASA-2020-0478)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0478");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0478.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27903");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/THY4LKGUS3D4XE5YHKLMTPVLURQ7OV57/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjpeg2' package(s) announced via the MGASA-2020-0478 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"There's a flaw in openjpeg in src/lib/openjp2/pi.c. When an attacker is able to
provide crafted input to be processed by the openjpeg encoder, this could cause
an out-of-bounds read. The greatest impact from this flaw is to application
availability (CVE-2020-27841).

There's a flaw in openjpeg's t2 encoder. An attacker who is able to provide
crafted input to be processed by openjpeg could cause a null pointer
dereference. The highest impact of this flaw is to application availability
(CVE-2020-27842).

A flaw was found in OpenJPEG. This flaw allows an attacker to provide specially
crafted input to the conversion or encoding functionality, causing an
out-of-bounds read. The highest threat from this vulnerability is system
availability (CVE-2020-27843).

There's a flaw in src/lib/openjp2/pi.c of openjpeg. If an attacker is able to
provide untrusted input to openjpeg's conversion/encoding functionality, they
could cause an out-of-bounds read. The highest impact of this flaw is to
application availability (CVE-2020-27845).");

  script_tag(name:"affected", value:"'openjpeg2' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64openjp2_7", rpm:"lib64openjp2_7~2.3.1~1.6.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openjpeg2-devel", rpm:"lib64openjpeg2-devel~2.3.1~1.6.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2_7", rpm:"libopenjp2_7~2.3.1~1.6.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjpeg2-devel", rpm:"libopenjpeg2-devel~2.3.1~1.6.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2", rpm:"openjpeg2~2.3.1~1.6.mga7", rls:"MAGEIA7"))) {
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
