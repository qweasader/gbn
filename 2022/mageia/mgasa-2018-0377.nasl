# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0377");
  script_cve_id("CVE-2018-14598", "CVE-2018-14599", "CVE-2018-14600");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-06 17:15:00 +0000 (Tue, 06 Aug 2019)");

  script_name("Mageia: Security Advisory (MGASA-2018-0377)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0377");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0377.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23474");
  script_xref(name:"URL", value:"https://openwall.com/lists/oss-security/2018/08/21/6");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2018-08/msg00164.html");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/3758-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libx11' package(s) announced via the MGASA-2018-0377 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated libx11 packages fix security vulnerabilities:

An issue was discovered in XListExtensions in ListExt.c in libX11 through
1.6.5. A malicious server can send a reply in which the first string
overflows, causing a variable to be set to NULL that will be freed later
on, leading to DoS (segmentation fault) (CVE-2018-14598).

An issue was discovered in libX11 through 1.6.5. The function
XListExtensions in ListExt.c is vulnerable to an off-by-one error caused
by malicious server responses, leading to DoS or possibly unspecified
other impact (CVE-2018-14599).

An issue was discovered in libX11 through 1.6.5. The function
XListExtensions in ListExt.c interprets a variable as signed instead of
unsigned, resulting in an out-of-bounds write (of up to 128 bytes),
leading to DoS or remote code execution (CVE-2018-14600).");

  script_tag(name:"affected", value:"'libx11' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64x11-devel", rpm:"lib64x11-devel~1.6.5~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64x11-xcb1", rpm:"lib64x11-xcb1~1.6.5~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64x11_6", rpm:"lib64x11_6~1.6.5~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11", rpm:"libx11~1.6.5~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11-common", rpm:"libx11-common~1.6.5~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11-devel", rpm:"libx11-devel~1.6.5~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11-doc", rpm:"libx11-doc~1.6.5~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11-xcb1", rpm:"libx11-xcb1~1.6.5~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11_6", rpm:"libx11_6~1.6.5~1.1.mga6", rls:"MAGEIA6"))) {
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
