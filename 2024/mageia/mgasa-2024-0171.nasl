# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0171");
  script_cve_id("CVE-2024-29040");
  script_tag(name:"creation_date", value:"2024-05-09 04:11:51 +0000 (Thu, 09 May 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0171)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0171");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0171.html");
  script_xref(name:"URL", value:"https://access.redhat.com/security/cve/CVE-2024-29040");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33176");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tpm2-tss' package(s) announced via the MGASA-2024-0171 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the tpm2-tss package, where there was no check that
the magic number in the attest is equal to the
TPM2_GENERATED_VALUE. This flaw allows an attacker to generate arbitrary
quote data, which may not be detected by Fapi_VerifyQuote.");

  script_tag(name:"affected", value:"'tpm2-tss' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"lib64tpm2-tss-devel", rpm:"lib64tpm2-tss-devel~4.0.2~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tss2-esys0", rpm:"lib64tss2-esys0~4.0.2~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tss2-fapi1", rpm:"lib64tss2-fapi1~4.0.2~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tss2-mu0", rpm:"lib64tss2-mu0~4.0.2~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tss2-policy0", rpm:"lib64tss2-policy0~4.0.2~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tss2-rc0", rpm:"lib64tss2-rc0~4.0.2~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tss2-sys1", rpm:"lib64tss2-sys1~4.0.2~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tss2-tcti-cmd0", rpm:"lib64tss2-tcti-cmd0~4.0.2~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tss2-tcti-device0", rpm:"lib64tss2-tcti-device0~4.0.2~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tss2-tcti-mssim0", rpm:"lib64tss2-tcti-mssim0~4.0.2~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tss2-tcti-pcap0", rpm:"lib64tss2-tcti-pcap0~4.0.2~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tss2-tcti-spi-helper0", rpm:"lib64tss2-tcti-spi-helper0~4.0.2~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tss2-tcti-swtpm0", rpm:"lib64tss2-tcti-swtpm0~4.0.2~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64tss2-tctildr0", rpm:"lib64tss2-tctildr0~4.0.2~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtpm2-tss-devel", rpm:"libtpm2-tss-devel~4.0.2~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0", rpm:"libtss2-esys0~4.0.2~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-fapi1", rpm:"libtss2-fapi1~4.0.2~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0", rpm:"libtss2-mu0~4.0.2~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-policy0", rpm:"libtss2-policy0~4.0.2~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-rc0", rpm:"libtss2-rc0~4.0.2~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys1", rpm:"libtss2-sys1~4.0.2~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-cmd0", rpm:"libtss2-tcti-cmd0~4.0.2~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0", rpm:"libtss2-tcti-device0~4.0.2~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0", rpm:"libtss2-tcti-mssim0~4.0.2~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-pcap0", rpm:"libtss2-tcti-pcap0~4.0.2~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-spi-helper0", rpm:"libtss2-tcti-spi-helper0~4.0.2~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-swtpm0", rpm:"libtss2-tcti-swtpm0~4.0.2~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tctildr0", rpm:"libtss2-tctildr0~4.0.2~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2-tss", rpm:"tpm2-tss~4.0.2~1.mga9", rls:"MAGEIA9"))) {
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
