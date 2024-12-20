# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0226");
  script_cve_id("CVE-2015-3885");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0226)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0226");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0226.html");
  script_xref(name:"URL", value:"http://www.ocert.org/advisories/ocert-2015-006.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15927");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rawtherapee' package(s) announced via the MGASA-2015-0226 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated rawtherapee package fixes security vulnerability:

The dcraw tool suffers from an integer overflow condition which lead to a
buffer overflow. The vulnerability concerns the 'len' variable, parsed without
validation from opened images, used in the ljpeg_start() function. A
maliciously crafted raw image file can be used to trigger the vulnerability,
causing a Denial of Service condition (CVE-2015-3885).

The rawtherapee package contains a bundled copy of the affected code and has
been patched to fix this issue.");

  script_tag(name:"affected", value:"'rawtherapee' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"rawtherapee", rpm:"rawtherapee~4.0.11~2.2.mga4", rls:"MAGEIA4"))) {
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
