# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0041");
  script_cve_id("CVE-2020-29361", "CVE-2020-29362", "CVE-2020-29363");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-07 19:50:40 +0000 (Thu, 07 Jan 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0041)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0041");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0041.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27853");
  script_xref(name:"URL", value:"https://github.com/p11-glue/p11-kit/releases/tag/0.23.22");
  script_xref(name:"URL", value:"https://github.com/p11-glue/p11-kit/security/advisories/GHSA-5j67-fw89-fp6x");
  script_xref(name:"URL", value:"https://github.com/p11-glue/p11-kit/security/advisories/GHSA-5wpq-43j2-6qwc");
  script_xref(name:"URL", value:"https://github.com/p11-glue/p11-kit/security/advisories/GHSA-q4r3-hm6m-mvc2");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/4D5CLBYQ6GQU5KRRIBTSC4AOKNPX2JPE/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'p11-kit' package(s) announced via the MGASA-2021-0041 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple integer overflows have been discovered in the array allocations in
the p11-kit library and the p11-kit list command, where overflow checks are
missing before calling realloc or calloc (CVE-2020-29361).

A heap-based buffer over-read has been discovered in the RPC protocol used by
the p11-kit server/remote commands and the client library. When the remote
entity supplies a byte array through a serialized PKCS#11 function call, the
receiving entity may allow the reading of up to 4 bytes of memory past the
heap allocation (CVE-2020-29362).

A heap-based buffer overflow has been discovered in the RPC protocol used by
p11-kit server/remote commands and the client library. When the remote entity
supplies a serialized byte array in a CK_ATTRIBUTE, the receiving entity may
not allocate sufficient length for the buffer to store the deserialized value
(CVE-2020-29363).");

  script_tag(name:"affected", value:"'p11-kit' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64p11-kit-devel", rpm:"lib64p11-kit-devel~0.23.22~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64p11-kit0", rpm:"lib64p11-kit0~0.23.22~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libp11-kit-devel", rpm:"libp11-kit-devel~0.23.22~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libp11-kit0", rpm:"libp11-kit0~0.23.22~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p11-kit", rpm:"p11-kit~0.23.22~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"p11-kit-trust", rpm:"p11-kit-trust~0.23.22~1.mga7", rls:"MAGEIA7"))) {
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
