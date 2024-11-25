# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0174");
  script_cve_id("CVE-2013-6369");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0174)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0174");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0174.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13174");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1032273");
  script_xref(name:"URL", value:"https://www.cl.cam.ac.uk/~mgk25/jbigkit/CHANGES");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jbigkit' package(s) announced via the MGASA-2014-0174 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated jbigkit packages fix security vulnerability:

Florian Weimer found a stack-based buffer overflow flaw in the libjbig library
(part of jbigkit). A specially-crafted image file read by libjbig could be
used to cause a program linked to libjbig to crash or, potentially, to execute
arbitrary code (CVE-2013-6369).

The jbigkit package has been updated to version 2.1, which fixes this issue,
as well as a few other bugs, including the ability of corrupted input data to
force the jbig85 decoder into an end-less loop.");

  script_tag(name:"affected", value:"'jbigkit' package(s) on Mageia 3, Mageia 4.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"jbigkit", rpm:"jbigkit~2.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64jbig-devel", rpm:"lib64jbig-devel~2.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64jbig1", rpm:"lib64jbig1~2.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjbig-devel", rpm:"libjbig-devel~2.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjbig1", rpm:"libjbig1~2.1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"jbigkit", rpm:"jbigkit~2.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64jbig-devel", rpm:"lib64jbig-devel~2.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64jbig1", rpm:"lib64jbig1~2.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjbig-devel", rpm:"libjbig-devel~2.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjbig1", rpm:"libjbig1~2.1~1.mga4", rls:"MAGEIA4"))) {
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
