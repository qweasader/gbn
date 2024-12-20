# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0084");
  script_cve_id("CVE-2016-2399");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-05 20:23:25 +0000 (Sun, 05 Feb 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0084)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0084");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0084.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20357");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/show_bug.cgi?id=1022805");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2017-02/msg00102.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libquicktime' package(s) announced via the MGASA-2017-0084 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Integer overflow in the quicktime_read_pascal function in libquicktime
1.2.4 and earlier allows remote attackers to cause a denial of service or
possibly have other unspecified impact via a crafted hdlr MP4 atom.
(CVE-2016-2399)");

  script_tag(name:"affected", value:"'libquicktime' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"lib64quicktime-devel", rpm:"lib64quicktime-devel~1.2.4~10.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64quicktime-devel", rpm:"lib64quicktime-devel~1.2.4~10.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64quicktime0", rpm:"lib64quicktime0~1.2.4~10.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64quicktime0", rpm:"lib64quicktime0~1.2.4~10.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquicktime", rpm:"libquicktime~1.2.4~10.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquicktime", rpm:"libquicktime~1.2.4~10.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquicktime-devel", rpm:"libquicktime-devel~1.2.4~10.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquicktime-devel", rpm:"libquicktime-devel~1.2.4~10.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquicktime-dv", rpm:"libquicktime-dv~1.2.4~10.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquicktime-dv", rpm:"libquicktime-dv~1.2.4~10.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquicktime-faad", rpm:"libquicktime-faad~1.2.4~10.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquicktime-lame", rpm:"libquicktime-lame~1.2.4~10.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquicktime-progs", rpm:"libquicktime-progs~1.2.4~10.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquicktime-progs", rpm:"libquicktime-progs~1.2.4~10.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquicktime-x264", rpm:"libquicktime-x264~1.2.4~10.1.mga5.tainted", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquicktime0", rpm:"libquicktime0~1.2.4~10.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libquicktime0", rpm:"libquicktime0~1.2.4~10.1.mga5.tainted", rls:"MAGEIA5"))) {
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
