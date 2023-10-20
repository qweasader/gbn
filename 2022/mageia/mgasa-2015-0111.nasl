# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0111");
  script_cve_id("CVE-2015-0209", "CVE-2015-0286", "CVE-2015-0287", "CVE-2015-0288", "CVE-2015-0289", "CVE-2015-0293");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0111)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0111");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0111.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15530");
  script_xref(name:"URL", value:"http://openssl.org/news/secadv_20150319.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the MGASA-2015-0111 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated openssl packages fix security vulnerabilities:

The function ASN1_TYPE_cmp will crash with an invalid read if an attempt is
made to compare ASN.1 boolean types. Since ASN1_TYPE_cmp is used to check
certificate signature algorithm consistency this can be used to crash any
certificate verification operation and exploited in a DoS attack. Any
application which performs certificate verification is vulnerable including
OpenSSL clients and servers which enable client authentication
(CVE-2015-0286).

Reusing a structure in ASN.1 parsing may allow an attacker to cause
memory corruption via an invalid write. Such reuse is and has been
strongly discouraged and is believed to be rare. Certificate parsing,
OpenSSL clients, and OpenSSL servers are not affected (CVE-2015-0287).

The PKCS#7 parsing code does not handle missing outer ContentInfo correctly.
An attacker can craft malformed ASN.1-encoded PKCS#7 blobs with
missing content and trigger a NULL pointer dereference on parsing.
OpenSSL clients and servers are not affected (CVE-2015-0289).

A malicious client can trigger an OPENSSL_assert (i.e., an abort) in
servers that both support SSLv2 and enable export cipher suites by sending
a specially crafted SSLv2 CLIENT-MASTER-KEY message (CVE-2015-0293).

A malformed EC private key file consumed via the d2i_ECPrivateKey function
could cause a use after free condition. This, in turn, could cause a double
free in several private key parsing functions (such as d2i_PrivateKey
or EVP_PKCS82PKEY) and could lead to a DoS attack or memory corruption
for applications that receive EC private keys from untrusted
sources. This scenario is considered rare (CVE-2015-0209).

The function X509_to_X509_REQ will crash with a NULL pointer dereference if
the certificate key is invalid. This function is rarely used in practice
(CVE-2015-0288).");

  script_tag(name:"affected", value:"'openssl' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl-devel", rpm:"lib64openssl-devel~1.0.1m~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl-engines1.0.0", rpm:"lib64openssl-engines1.0.0~1.0.1m~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl-static-devel", rpm:"lib64openssl-static-devel~1.0.1m~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl1.0.0", rpm:"lib64openssl1.0.0~1.0.1m~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-devel", rpm:"libopenssl-devel~1.0.1m~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-engines1.0.0", rpm:"libopenssl-engines1.0.0~1.0.1m~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-static-devel", rpm:"libopenssl-static-devel~1.0.1m~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1.0.0", rpm:"libopenssl1.0.0~1.0.1m~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1m~1.mga4", rls:"MAGEIA4"))) {
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
