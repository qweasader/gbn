# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0360");
  script_cve_id("CVE-2021-22918");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 17:57:00 +0000 (Tue, 20 Jul 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0360)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0360");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0360.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29231");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/july-2021-security-releases/");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4936");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5007-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libuv' package(s) announced via the MGASA-2021-0360 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Node.js before 16.4.1, 14.17.2, 12.22.2 is vulnerable to an out-of-bounds
read when uv__idna_toascii() is used to convert strings to ASCII. The pointer
p is read and increased without checking whether it is beyond pe, with the
latter holding a pointer to the end of the buffer. This can lead to
information disclosures or crashes. This function can be triggered via
uv_getaddrinfo(). (CVE-2021-22918).");

  script_tag(name:"affected", value:"'libuv' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64uv-devel", rpm:"lib64uv-devel~1.40.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64uv-static-devel", rpm:"lib64uv-static-devel~1.40.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64uv1", rpm:"lib64uv1~1.40.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuv", rpm:"libuv~1.40.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuv-devel", rpm:"libuv-devel~1.40.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuv-static-devel", rpm:"libuv-static-devel~1.40.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuv1", rpm:"libuv1~1.40.0~1.1.mga8", rls:"MAGEIA8"))) {
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
