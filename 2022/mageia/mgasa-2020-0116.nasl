# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0116");
  script_cve_id("CVE-2019-14275", "CVE-2019-19555", "CVE-2019-19746", "CVE-2019-19797");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-24 17:53:16 +0000 (Fri, 24 Apr 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0116)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0116");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0116.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26146");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/7DHT2H26YTJQC3SPYPFUPZZJG26MWGTL/");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2073");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'transfig' package(s) announced via the MGASA-2020-0116 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated package fixes security vulnerabilities:

Xfig fig2dev 3.2.7a has a stack-based buffer overflow in the calc_arrow
function in bound.c. (CVE-2019-14275)

read_textobject in read.c in Xfig fig2dev 3.2.7b has a stack-based buffer
overflow because of an incorrect sscanf. (CVE-2019-19555)

make_arrow in arrow.c in Xfig fig2dev 3.2.7b allows a segmentation fault
and out-of-bounds write because of an integer overflow via a large arrow
type. (CVE-2019-19746)

read_colordef in read.c in Xfig fig2dev 3.2.7b has an out-of-bounds write.
(CVE-2019-19797)");

  script_tag(name:"affected", value:"'transfig' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"transfig", rpm:"transfig~3.2.7a~3.1.mga7", rls:"MAGEIA7"))) {
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
