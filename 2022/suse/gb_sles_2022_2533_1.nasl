# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2533.1");
  script_cve_id("CVE-2021-43527", "CVE-2022-31741");
  script_tag(name:"creation_date", value:"2022-07-25 04:39:53 +0000 (Mon, 25 Jul 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-16 14:32:02 +0000 (Thu, 16 Dec 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2533-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0|SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2533-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222533-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozilla-nss' package(s) announced via the SUSE-SU-2022:2533-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mozilla-nss fixes the following issues:

Various FIPS 140-3 related fixes were backported from SUSE Linux Enterprise 15 SP4:

Makes the PBKDF known answer test compliant with NIST SP800-132.
 (bsc#1192079).

FIPS: Add on-demand integrity tests through
 sftk_FIPSRepeatIntegrityCheck() (bsc#1198980).

FIPS: mark algorithms as approved/non-approved according to security
 policy (bsc#1191546, bsc#1201298).

FIPS: remove hard disabling of unapproved algorithms. This requirement
 is now fulfilled by the service level indicator (bsc#1200325).

Run test suite at build time, and make it pass (bsc#1198486).

FIPS: skip algorithms that are hard disabled in FIPS mode.

Prevent expired PayPalEE cert from failing the tests.

Allow checksumming to be disabled, but only if we entered FIPS mode due
 to NSS_FIPS being set, not if it came from /proc.

FIPS: Make the PBKDF known answer test compliant with NIST SP800-132.

Update FIPS validation string to version-release format.

FIPS: remove XCBC MAC from list of FIPS approved algorithms.

Enable NSS_ENABLE_FIPS_INDICATORS and set NSS_FIPS_MODULE_ID for build.

FIPS: claim 3DES unapproved in FIPS mode (bsc#1192080).

FIPS: allow testing of unapproved algorithms (bsc#1192228).

FIPS: add version indicators. (bmo#1729550, bsc#1192086).

FIPS: fix some secret clearing (bmo#1697303, bsc#1192087).

Version update to NSS 3.79:

Use PK11_GetSlotInfo instead of raw C_GetSlotInfo calls.

Update mercurial in clang-format docker image.

Use of uninitialized pointer in lg_init after alloc fail.

selfserv and tstclnt should use PR_GetPrefLoopbackAddrInfo.

Add SECMOD_LockedModuleHasRemovableSlots.

Fix secasn1d parsing of indefinite SEQUENCE inside indefinite GROUP.

Added RFC8422 compliant TLS <= 1.2 undefined/compressed ECPointFormat
 extension alerts.

TLS 1.3 Server: Send protocol_version alert on unsupported
 ClientHello.legacy_version.

Correct invalid record inner and outer content type alerts.

NSS does not properly import or export pkcs12 files with large passwords
 and pkcs5v2 encoding.

improve error handling after nssCKFWInstance_CreateObjectHandle.

Initialize pointers passed to NSS_CMSDigestContext_FinishMultiple.

NSS 3.79 should depend on NSPR 4.34

Version update to NSS 3.78.1:

Initialize pointers passed to NSS_CMSDigestContext_FinishMultiple

Version update to NSS 3.78:

Added TLS 1.3 zero-length inner plaintext checks and tests, zero-length
 record/fragment handling tests.

Reworked overlong record size checks and added TLS1.3 specific
 boundaries.

Add ECH Grease Support to tstclnt

Add a strict variant of moz::pkix::CheckCertHostname.

Change SSL_REUSE_SERVER_ECDHE_KEY default to false.

Make SEC_PKCS12EnableCipher succeed

Update zlib in NSS to 1.2.12.

Version update to NSS 3.77:

Fix link to TLS page on wireshark wiki

Add two D-TRUST 2020 root certificates.

Add Telia Root CA v2 root certificate.

Remove expired ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'mozilla-nss' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Enterprise Storage 7, SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Basesystem 15-SP4, SUSE Linux Enterprise Module for Server Applications 15-SP3, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Linux Enterprise Server for SAP 15-SP2, SUSE Manager Proxy 4.1, SUSE Manager Retail Branch Server 4.1, SUSE Manager Server 4.1.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.79~150000.3.74.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.79~150000.3.74.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit-debuginfo", rpm:"libfreebl3-32bit-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-debuginfo", rpm:"libfreebl3-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-hmac", rpm:"libfreebl3-hmac~3.79~150000.3.74.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-hmac-32bit", rpm:"libfreebl3-hmac-32bit~3.79~150000.3.74.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3", rpm:"libsoftokn3~3.79~150000.3.74.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-32bit", rpm:"libsoftokn3-32bit~3.79~150000.3.74.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-32bit-debuginfo", rpm:"libsoftokn3-32bit-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-debuginfo", rpm:"libsoftokn3-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-hmac", rpm:"libsoftokn3-hmac~3.79~150000.3.74.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-hmac-32bit", rpm:"libsoftokn3-hmac-32bit~3.79~150000.3.74.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.34~150000.3.23.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit-debuginfo", rpm:"mozilla-nspr-32bit-debuginfo~4.34~150000.3.23.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.34~150000.3.23.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debuginfo", rpm:"mozilla-nspr-debuginfo~4.34~150000.3.23.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debugsource", rpm:"mozilla-nspr-debugsource~4.34~150000.3.23.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-devel", rpm:"mozilla-nspr-devel~4.34~150000.3.23.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.79~150000.3.74.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.79~150000.3.74.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit-debuginfo", rpm:"mozilla-nss-32bit-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs", rpm:"mozilla-nss-certs~3.79~150000.3.74.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-32bit", rpm:"mozilla-nss-certs-32bit~3.79~150000.3.74.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-32bit-debuginfo", rpm:"mozilla-nss-certs-32bit-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo", rpm:"mozilla-nss-certs-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debuginfo", rpm:"mozilla-nss-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debugsource", rpm:"mozilla-nss-debugsource~3.79~150000.3.74.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.79~150000.3.74.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit", rpm:"mozilla-nss-sysinit~3.79~150000.3.74.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo", rpm:"mozilla-nss-sysinit-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.79~150000.3.74.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools-debuginfo", rpm:"mozilla-nss-tools-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.34~150000.3.23.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit-debuginfo", rpm:"mozilla-nspr-32bit-debuginfo~4.34~150000.3.23.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.34~150000.3.23.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debuginfo", rpm:"mozilla-nspr-debuginfo~4.34~150000.3.23.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debugsource", rpm:"mozilla-nspr-debugsource~4.34~150000.3.23.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-devel", rpm:"mozilla-nspr-devel~4.34~150000.3.23.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.79~150000.3.74.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-debuginfo", rpm:"libfreebl3-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-hmac", rpm:"libfreebl3-hmac~3.79~150000.3.74.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3", rpm:"libsoftokn3~3.79~150000.3.74.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-debuginfo", rpm:"libsoftokn3-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-hmac", rpm:"libsoftokn3-hmac~3.79~150000.3.74.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.34~150000.3.23.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debuginfo", rpm:"mozilla-nspr-debuginfo~4.34~150000.3.23.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debugsource", rpm:"mozilla-nspr-debugsource~4.34~150000.3.23.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-devel", rpm:"mozilla-nspr-devel~4.34~150000.3.23.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.79~150000.3.74.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs", rpm:"mozilla-nss-certs~3.79~150000.3.74.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo", rpm:"mozilla-nss-certs-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debuginfo", rpm:"mozilla-nss-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debugsource", rpm:"mozilla-nss-debugsource~3.79~150000.3.74.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.79~150000.3.74.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit", rpm:"mozilla-nss-sysinit~3.79~150000.3.74.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo", rpm:"mozilla-nss-sysinit-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.79~150000.3.74.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools-debuginfo", rpm:"mozilla-nss-tools-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.79~150000.3.74.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.79~150000.3.74.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit-debuginfo", rpm:"libfreebl3-32bit-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-debuginfo", rpm:"libfreebl3-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-hmac", rpm:"libfreebl3-hmac~3.79~150000.3.74.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-hmac-32bit", rpm:"libfreebl3-hmac-32bit~3.79~150000.3.74.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3", rpm:"libsoftokn3~3.79~150000.3.74.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-32bit", rpm:"libsoftokn3-32bit~3.79~150000.3.74.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-32bit-debuginfo", rpm:"libsoftokn3-32bit-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-debuginfo", rpm:"libsoftokn3-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-hmac", rpm:"libsoftokn3-hmac~3.79~150000.3.74.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-hmac-32bit", rpm:"libsoftokn3-hmac-32bit~3.79~150000.3.74.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.34~150000.3.23.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit-debuginfo", rpm:"mozilla-nspr-32bit-debuginfo~4.34~150000.3.23.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.34~150000.3.23.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debuginfo", rpm:"mozilla-nspr-debuginfo~4.34~150000.3.23.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debugsource", rpm:"mozilla-nspr-debugsource~4.34~150000.3.23.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-devel", rpm:"mozilla-nspr-devel~4.34~150000.3.23.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.79~150000.3.74.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.79~150000.3.74.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit-debuginfo", rpm:"mozilla-nss-32bit-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs", rpm:"mozilla-nss-certs~3.79~150000.3.74.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-32bit", rpm:"mozilla-nss-certs-32bit~3.79~150000.3.74.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-32bit-debuginfo", rpm:"mozilla-nss-certs-32bit-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo", rpm:"mozilla-nss-certs-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debuginfo", rpm:"mozilla-nss-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debugsource", rpm:"mozilla-nss-debugsource~3.79~150000.3.74.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.79~150000.3.74.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit", rpm:"mozilla-nss-sysinit~3.79~150000.3.74.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo", rpm:"mozilla-nss-sysinit-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.79~150000.3.74.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools-debuginfo", rpm:"mozilla-nss-tools-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.79~150000.3.74.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.79~150000.3.74.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit-debuginfo", rpm:"libfreebl3-32bit-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-debuginfo", rpm:"libfreebl3-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-hmac", rpm:"libfreebl3-hmac~3.79~150000.3.74.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-hmac-32bit", rpm:"libfreebl3-hmac-32bit~3.79~150000.3.74.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3", rpm:"libsoftokn3~3.79~150000.3.74.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-32bit", rpm:"libsoftokn3-32bit~3.79~150000.3.74.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-32bit-debuginfo", rpm:"libsoftokn3-32bit-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-debuginfo", rpm:"libsoftokn3-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-hmac", rpm:"libsoftokn3-hmac~3.79~150000.3.74.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-hmac-32bit", rpm:"libsoftokn3-hmac-32bit~3.79~150000.3.74.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit", rpm:"mozilla-nspr-32bit~4.34~150000.3.23.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-32bit-debuginfo", rpm:"mozilla-nspr-32bit-debuginfo~4.34~150000.3.23.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr", rpm:"mozilla-nspr~4.34~150000.3.23.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debuginfo", rpm:"mozilla-nspr-debuginfo~4.34~150000.3.23.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-debugsource", rpm:"mozilla-nspr-debugsource~4.34~150000.3.23.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nspr-devel", rpm:"mozilla-nspr-devel~4.34~150000.3.23.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.79~150000.3.74.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.79~150000.3.74.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit-debuginfo", rpm:"mozilla-nss-32bit-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs", rpm:"mozilla-nss-certs~3.79~150000.3.74.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-32bit", rpm:"mozilla-nss-certs-32bit~3.79~150000.3.74.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-32bit-debuginfo", rpm:"mozilla-nss-certs-32bit-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo", rpm:"mozilla-nss-certs-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debuginfo", rpm:"mozilla-nss-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debugsource", rpm:"mozilla-nss-debugsource~3.79~150000.3.74.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.79~150000.3.74.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit", rpm:"mozilla-nss-sysinit~3.79~150000.3.74.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo", rpm:"mozilla-nss-sysinit-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.79~150000.3.74.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools-debuginfo", rpm:"mozilla-nss-tools-debuginfo~3.79~150000.3.74.1", rls:"SLES15.0SP2"))) {
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
