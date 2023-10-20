# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0373");
  script_cve_id("CVE-2021-29477", "CVE-2021-29478", "CVE-2021-32761");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-09 09:15:00 +0000 (Fri, 09 Jul 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0373)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0373");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0373.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29036");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/BPWBIZXA67JFIB63W2CNVVILCGIC2ME5/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/BHWOF7CBVUGDK3AN6H3BN3VNTH2TDUZZ/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/SN7INTZFE34MIQJO7WDDTIY5LIBGN6GI/");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2717");
  script_xref(name:"URL", value:"https://github.com/redis/redis/security/advisories/GHSA-8wxq-j7rp-g8wj");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'redis' package(s) announced via the MGASA-2021-0373 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An integer overflow bug in Redis version 6.0 or newer could be exploited using
the `STRALGO LCS` command to corrupt the heap and potentially result with
remote code execution (CVE-2021-29477).

An integer overflow bug in Redis 6.2 before 6.2.3 could be exploited to corrupt
the heap and potentially result with remote code execution (CVE-2021-29478).

A vulnerability involving out-of-bounds read and integer overflow to buffer
overflow exists starting with version 2.2 and prior to versions 5.0.13, 6.0.15
and 6.2.5. On 32-bit systems, Redis `*BIT*` command are vulnerable to integer
overflow that can potentially be exploited to corrupt the heap, leak arbitrary
heap contents or trigger remote code execution (CVE-2021-32761).");

  script_tag(name:"affected", value:"'redis' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"redis", rpm:"redis~6.0.15~1.mga8", rls:"MAGEIA8"))) {
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
