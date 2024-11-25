# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0465");
  script_cve_id("CVE-2020-1968", "CVE-2020-1971");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-15 19:44:02 +0000 (Tue, 15 Dec 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0465)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0465");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0465.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27305");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4504-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4662-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4807");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20200909.txt");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20201208.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'compat-openssl10' package(s) announced via the MGASA-2020-0465 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Raccoon attack exploits a flaw in the TLS specification which can lead
to an attacker being able to compute the pre-master secret in connections
which have used a Diffie-Hellman (DH) based ciphersuite. In such a case this
would result in the attacker being able to eavesdrop on all encrypted
communications sent over that TLS connection. The attack can only be exploited
if an implementation re-uses a DH secret across multiple TLS connections.
Note that this issue only impacts DH ciphersuites and not ECDH ciphersuites.
(CVE-2020-1968)

The X.509 GeneralName type is a generic type for representing different types
of names. One of those name types is known as EDIPartyName.
OpenSSL provides a function GENERAL_NAME_cmp which compares different
instances of a GENERAL_NAME to see if they are equal or not. This function
behaves incorrectly when both GENERAL_NAMEs contain an EDIPARTYNAME.
A NULL pointer dereference and a crash may occur leading to a possible
denial of service attack. OpenSSL itself uses the GENERAL_NAME_cmp function
for two purposes:
1) Comparing CRL distribution point names between an available CRL and a
CRL distribution point embedded in an X509 certificate
2) When verifying that a timestamp response token signer matches the
timestamp authority name (exposed via the API functions TS_RESP_verify_response
and TS_RESP_verify_token)
If an attacker can control both items being compared then that attacker
could trigger a crash. For example if the attacker can trick a client or
server into checking a malicious certificate against a malicious CRL then
this may occur.
Note that some applications automatically download CRLs based on a URL
embedded in a certificate. This checking happens prior to the signatures on
the certificate and CRL being verified. OpenSSL's s_server, s_client and
verify tools have support for the '-crl_download' option which implements
automatic CRL downloading and this attack has been demonstrated to work
against those tools. Note that an unrelated bug means that affected versions
of OpenSSL cannot parse or construct correct encodings of EDIPARTYNAME.
However it is possible to construct a malformed EDIPARTYNAME that OpenSSL's
parser will accept and hence trigger this attack.
(CVE-2020-1971)");

  script_tag(name:"affected", value:"'compat-openssl10' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"compat-openssl10", rpm:"compat-openssl10~1.0.2u~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64compat-openssl10-devel", rpm:"lib64compat-openssl10-devel~1.0.2u~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64compat-openssl10_1.0.0", rpm:"lib64compat-openssl10_1.0.0~1.0.2u~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcompat-openssl10-devel", rpm:"libcompat-openssl10-devel~1.0.2u~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcompat-openssl10_1.0.0", rpm:"libcompat-openssl10_1.0.0~1.0.2u~1.1.mga7", rls:"MAGEIA7"))) {
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
