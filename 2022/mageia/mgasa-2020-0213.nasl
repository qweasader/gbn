# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0213");
  script_cve_id("CVE-2020-12268");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-29 19:18:40 +0000 (Wed, 29 Apr 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0213)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0213");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0213.html");
  script_xref(name:"URL", value:"http://lists.suse.com/pipermail/sle-security-updates/2020-May/006802.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26601");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jbig2dec' package(s) announced via the MGASA-2020-0213 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated jbig2dec packages fix security vulnerability:

jbig2_image_compose in jbig2_image.c in Artifex jbig2dec before 0.18
has a heap-based buffer overflow (CVE-2020-12268).");

  script_tag(name:"affected", value:"'jbig2dec' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"jbig2dec", rpm:"jbig2dec~0.18~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64jbig2dec-devel", rpm:"lib64jbig2dec-devel~0.18~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64jbig2dec0", rpm:"lib64jbig2dec0~0.18~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjbig2dec-devel", rpm:"libjbig2dec-devel~0.18~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjbig2dec0", rpm:"libjbig2dec0~0.18~1.mga7", rls:"MAGEIA7"))) {
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
