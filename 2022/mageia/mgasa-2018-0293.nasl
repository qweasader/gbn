# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0293");
  script_cve_id("CVE-2017-18269", "CVE-2018-11236");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-18 16:29:00 +0000 (Fri, 18 May 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0293)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0293");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0293.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23136");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-06/msg00010.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc' package(s) announced via the MGASA-2018-0293 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated glibc packages fix security vulnerabilities:

An SSE2-optimized memmove implementation for i386 in
sysdeps/i386/i686/multiarch/memcpy-sse2-unaligned.S in the GNU C Library (aka
glibc or libc6) 2.21 through 2.27 does not correctly perform the overlapping
memory check if the source memory range spans the middle of the address space,
resulting in corrupt data being produced by the copy operation. This may
disclose information to context-dependent attackers, or result in a denial of
service, or, possibly, code execution (CVE-2017-18269).

stdlib/canonicalize.c in the GNU C Library (aka glibc or libc6) 2.27 and
earlier, when processing very long pathname arguments to the realpath function,
could encounter an integer overflow on 32-bit architectures, leading to a
stack-based buffer overflow and, potentially, arbitrary code execution
(CVE-2018-11236).");

  script_tag(name:"affected", value:"'glibc' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.22~29.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.22~29.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-doc", rpm:"glibc-doc~2.22~29.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-i18ndata", rpm:"glibc-i18ndata~2.22~29.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-profile", rpm:"glibc-profile~2.22~29.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-static-devel", rpm:"glibc-static-devel~2.22~29.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.22~29.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.22~29.mga6", rls:"MAGEIA6"))) {
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
