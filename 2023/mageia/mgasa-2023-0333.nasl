# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0333");
  script_cve_id("CVE-2023-43907");
  script_tag(name:"creation_date", value:"2023-12-04 04:12:23 +0000 (Mon, 04 Dec 2023)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-03 20:57:20 +0000 (Tue, 03 Oct 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0333)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(8|9)");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0333");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0333.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32520");
  script_xref(name:"URL", value:"https://github.com/Frank-Z7/z-vulnerabilitys/blob/main/optipng-global-buffer-overflow1/optipng-global-buffer-overflow1.md");
  script_xref(name:"URL", value:"https://sourceforge.net/p/optipng/bugs/87/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'optipng' package(s) announced via the MGASA-2023-0333 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated the optipng package to fix a security vulnerability
(CVE-2023-43907) and other bugs. The GIF handler was vulnerable to a
global buffer overflow.");

  script_tag(name:"affected", value:"'optipng' package(s) on Mageia 8, Mageia 9.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"optipng", rpm:"optipng~0.7.8~2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"optipng", rpm:"optipng~0.7.8~2.mga9", rls:"MAGEIA9"))) {
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
