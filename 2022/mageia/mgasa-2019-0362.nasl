# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0362");
  script_cve_id("CVE-2019-14318");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-12 12:31:26 +0000 (Mon, 12 Aug 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0362)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0362");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0362.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25759");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2019-08/msg00155.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libcryptopp' package(s) announced via the MGASA-2019-0362 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix a security vulnerability:

Crypto++ 8.3.0 and earlier contains a timing side channel in ECDSA
signature generation. This allows a local or remote attacker, able to
measure the duration of hundreds to thousands of signing operations,
to compute the private key used. The issue occurs because scalar
multiplication in ecp.cpp (prime field curves, small leakage) and
algebra.cpp (binary field curves, large leakage) is not constant time
and leaks the bit length of the scalar among other information
(CVE-2019-14318).");

  script_tag(name:"affected", value:"'libcryptopp' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64cryptopp-devel", rpm:"lib64cryptopp-devel~7.0.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cryptopp7", rpm:"lib64cryptopp7~7.0.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcryptopp", rpm:"libcryptopp~7.0.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcryptopp-devel", rpm:"libcryptopp-devel~7.0.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcryptopp-progs", rpm:"libcryptopp-progs~7.0.0~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcryptopp7", rpm:"libcryptopp7~7.0.0~1.1.mga7", rls:"MAGEIA7"))) {
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
