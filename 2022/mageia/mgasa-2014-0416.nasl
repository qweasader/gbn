# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0416");
  script_cve_id("CVE-2014-3513", "CVE-2014-3566", "CVE-2014-3567");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2014-10-23 15:33:41 +0000 (Thu, 23 Oct 2014)");

  script_name("Mageia: Security Advisory (MGASA-2014-0416)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0416");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0416.html");
  script_xref(name:"URL", value:"https://access.redhat.com/articles/1232123");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14296");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2014-1652.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the MGASA-2014-0416 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update adds support for the TLS Fallback Signaling Cipher Suite Value
(TLS_FALLBACK_SCSV), which can be used to prevent protocol downgrade
attacks against applications which re-connect using a lower SSL/TLS
protocol version when the initial connection indicating the highest
supported protocol version fails.

This can prevent a forceful downgrade of the communication to SSL 3.0.
The SSL 3.0 protocol was found to be vulnerable to the padding oracle
attack when using block cipher suites in cipher block chaining (CBC) mode.
This issue is identified as CVE-2014-3566, and also known under the alias
POODLE. This SSL 3.0 protocol flaw will not be addressed in a future
update, it is recommended that users configure their applications to
require at least TLS protocol version 1.0 for secure communication.

For additional information about this flaw, see the RedHat Knowledgebase
article in the references.

A memory leak flaw was found in the way OpenSSL parsed the DTLS Secure
Real-time Transport Protocol (SRTP) extension data. A remote attacker could
send multiple specially crafted handshake messages to exhaust all available
memory of an SSL/TLS or DTLS server (CVE-2014-3513).

A memory leak flaw was found in the way an OpenSSL handled failed session
ticket integrity checks. A remote attacker could exhaust all available
memory of an SSL/TLS or DTLS server by sending a large number of invalid
session tickets to that server (CVE-2014-3567).");

  script_tag(name:"affected", value:"'openssl' package(s) on Mageia 3, Mageia 4.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl-devel", rpm:"lib64openssl-devel~1.0.1e~1.11.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl-engines1.0.0", rpm:"lib64openssl-engines1.0.0~1.0.1e~1.11.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl-static-devel", rpm:"lib64openssl-static-devel~1.0.1e~1.11.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl1.0.0", rpm:"lib64openssl1.0.0~1.0.1e~1.11.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-devel", rpm:"libopenssl-devel~1.0.1e~1.11.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-engines1.0.0", rpm:"libopenssl-engines1.0.0~1.0.1e~1.11.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-static-devel", rpm:"libopenssl-static-devel~1.0.1e~1.11.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1.0.0", rpm:"libopenssl1.0.0~1.0.1e~1.11.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1e~1.11.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl-devel", rpm:"lib64openssl-devel~1.0.1e~8.8.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl-engines1.0.0", rpm:"lib64openssl-engines1.0.0~1.0.1e~8.8.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl-static-devel", rpm:"lib64openssl-static-devel~1.0.1e~8.8.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openssl1.0.0", rpm:"lib64openssl1.0.0~1.0.1e~8.8.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-devel", rpm:"libopenssl-devel~1.0.1e~8.8.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-engines1.0.0", rpm:"libopenssl-engines1.0.0~1.0.1e~8.8.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-static-devel", rpm:"libopenssl-static-devel~1.0.1e~8.8.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1.0.0", rpm:"libopenssl1.0.0~1.0.1e~8.8.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~1.0.1e~8.8.mga4", rls:"MAGEIA4"))) {
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
