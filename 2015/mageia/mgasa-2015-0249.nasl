# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130127");
  script_cve_id("CVE-2015-1258");
  script_tag(name:"creation_date", value:"2015-10-15 07:43:02 +0000 (Thu, 15 Oct 2015)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0249)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(4|5)");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0249");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0249.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16019");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2015/05/stable-channel-update_19.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvpx' package(s) announced via the MGASA-2015-0249 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libvpx before 1.4.0 allows remote attackers to trigger a negative value
for a size field, and consequently cause a denial of service or possibly
have unspecified other impact, via a crafted frame size in VP9 video data
(CVE-2015-1258)");

  script_tag(name:"affected", value:"'libvpx' package(s) on Mageia 4, Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64vpx-devel", rpm:"lib64vpx-devel~1.3.0~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vpx1", rpm:"lib64vpx1~1.3.0~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx", rpm:"libvpx~1.3.0~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx-devel", rpm:"libvpx-devel~1.3.0~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx-utils", rpm:"libvpx-utils~1.3.0~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx1", rpm:"libvpx1~1.3.0~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"lib64vpx-devel", rpm:"lib64vpx-devel~1.3.0~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64vpx1", rpm:"lib64vpx1~1.3.0~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx", rpm:"libvpx~1.3.0~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx-devel", rpm:"libvpx-devel~1.3.0~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx-utils", rpm:"libvpx-utils~1.3.0~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvpx1", rpm:"libvpx1~1.3.0~3.1.mga5", rls:"MAGEIA5"))) {
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
