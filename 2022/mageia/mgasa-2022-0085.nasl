# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0085");
  script_cve_id("CVE-2021-0561");
  script_tag(name:"creation_date", value:"2022-03-07 04:10:01 +0000 (Mon, 07 Mar 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-24 13:12:51 +0000 (Thu, 24 Jun 2021)");

  script_name("Mageia: Security Advisory (MGASA-2022-0085)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0085");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0085.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30098");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/EWXBVMPPSL377I7YM55ZYXVKVMYOKES2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flac' package(s) announced via the MGASA-2022-0085 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In append_to_verify_fifo_interleaved_ of stream_encoder.c, there is a
possible out of bounds write due to a missing bounds check. This could
lead to local information disclosure with no additional execution
privileges needed. User interaction is not needed for exploitation.
(CVE-2021-0561)");

  script_tag(name:"affected", value:"'flac' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"flac", rpm:"flac~1.3.3~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64flac++-devel", rpm:"lib64flac++-devel~1.3.3~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64flac++6", rpm:"lib64flac++6~1.3.3~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64flac-devel", rpm:"lib64flac-devel~1.3.3~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64flac8", rpm:"lib64flac8~1.3.3~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libflac++-devel", rpm:"libflac++-devel~1.3.3~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libflac++6", rpm:"libflac++6~1.3.3~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libflac-devel", rpm:"libflac-devel~1.3.3~3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libflac8", rpm:"libflac8~1.3.3~3.1.mga8", rls:"MAGEIA8"))) {
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
