# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0094");
  script_cve_id("CVE-2017-2784");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-26 19:44:58 +0000 (Wed, 26 Apr 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0094)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0094");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0094.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20561");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2017-03/msg00072.html");
  script_xref(name:"URL", value:"https://tls.mbed.org/tech-updates/releases/mbedtls-2.4.2-2.1.7-and-1.3.19-released");
  script_xref(name:"URL", value:"https://tls.mbed.org/tech-updates/security-advisories/mbedtls-security-advisory-2017-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mbedtls' package(s) announced via the MGASA-2017-0094 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In mbedTLS before 1.3.19, if a malicious peer supplies a certificate with
a specially crafted secp224k1 public key, then an attacker can cause the
server or client to attempt to free block of memory held on stack.
Depending on the platform, this could result in a Denial of Service
(client crash) or potentially could be exploited to allow remote code
execution with the same privileges as the host application
(CVE-2017-2784).

The mbedtls package has been updated to version 1.3.19, fixing this issue
as well as other security issues and bugs.");

  script_tag(name:"affected", value:"'mbedtls' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64mbedtls-devel", rpm:"lib64mbedtls-devel~1.3.19~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mbedtls9", rpm:"lib64mbedtls9~1.3.19~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmbedtls-devel", rpm:"libmbedtls-devel~1.3.19~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmbedtls9", rpm:"libmbedtls9~1.3.19~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mbedtls", rpm:"mbedtls~1.3.19~1.mga5", rls:"MAGEIA5"))) {
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
