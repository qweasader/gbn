# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.0338.1");
  script_cve_id("CVE-2016-1930", "CVE-2016-1935", "CVE-2016-1938");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-02-09 19:26:10 +0000 (Tue, 09 Feb 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:0338-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:0338-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20160338-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox, MozillaFirefox-branding-SLE, mozilla-nss' package(s) announced via the SUSE-SU-2016:0338-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox, MozillaFirefox-branding-SLE, mozilla-nss fixes the following issues: (bsc#963520)
Mozilla Firefox was updated to 38.6.0 ESR. Mozilla NSS was updated to 3.20.2.
The following vulnerabilities were fixed:
- CVE-2016-1930: Memory safety bugs fixed in Firefox ESR 38.6 (bsc#963632)
- CVE-2016-1935: Buffer overflow in WebGL after out of memory allocation
 (bsc#963635)
- CVE-2016-1938: Calculations with mp_div and mp_exptmod in Network
 Security Services (NSS) canproduce wrong results (bsc#963731)
The following improvements were added:
- bsc#954447: Mozilla NSS now supports a number of new DHE ciphersuites
- Tracking protection is now enabled by default
- bsc#964332: Fixed leaking file descriptors inside FIPS selfcheck code");

  script_tag(name:"affected", value:"'MozillaFirefox, MozillaFirefox-branding-SLE, mozilla-nss' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Software Development Kit 12, SUSE Linux Enterprise Software Development Kit 12-SP1.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~38.6.0esr~57.3", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLE", rpm:"MozillaFirefox-branding-SLE~31.0~20.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~38.6.0esr~57.3", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~38.6.0esr~57.3", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~38.6.0esr~57.3", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.20.2~37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.20.2~37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-debuginfo", rpm:"libfreebl3-debuginfo~3.20.2~37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-debuginfo-32bit", rpm:"libfreebl3-debuginfo-32bit~3.20.2~37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-hmac", rpm:"libfreebl3-hmac~3.20.2~37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-hmac-32bit", rpm:"libfreebl3-hmac-32bit~3.20.2~37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3", rpm:"libsoftokn3~3.20.2~37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-32bit", rpm:"libsoftokn3-32bit~3.20.2~37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-debuginfo", rpm:"libsoftokn3-debuginfo~3.20.2~37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-debuginfo-32bit", rpm:"libsoftokn3-debuginfo-32bit~3.20.2~37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-hmac", rpm:"libsoftokn3-hmac~3.20.2~37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-hmac-32bit", rpm:"libsoftokn3-hmac-32bit~3.20.2~37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.20.2~37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.20.2~37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs", rpm:"mozilla-nss-certs~3.20.2~37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-32bit", rpm:"mozilla-nss-certs-32bit~3.20.2~37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo", rpm:"mozilla-nss-certs-debuginfo~3.20.2~37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo-32bit", rpm:"mozilla-nss-certs-debuginfo-32bit~3.20.2~37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debuginfo", rpm:"mozilla-nss-debuginfo~3.20.2~37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debuginfo-32bit", rpm:"mozilla-nss-debuginfo-32bit~3.20.2~37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debugsource", rpm:"mozilla-nss-debugsource~3.20.2~37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit", rpm:"mozilla-nss-sysinit~3.20.2~37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-32bit", rpm:"mozilla-nss-sysinit-32bit~3.20.2~37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo", rpm:"mozilla-nss-sysinit-debuginfo~3.20.2~37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo-32bit", rpm:"mozilla-nss-sysinit-debuginfo-32bit~3.20.2~37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.20.2~37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools-debuginfo", rpm:"mozilla-nss-tools-debuginfo~3.20.2~37.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~38.6.0esr~57.3", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-branding-SLE", rpm:"MozillaFirefox-branding-SLE~31.0~20.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~38.6.0esr~57.3", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~38.6.0esr~57.3", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations", rpm:"MozillaFirefox-translations~38.6.0esr~57.3", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.20.2~37.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.20.2~37.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-debuginfo", rpm:"libfreebl3-debuginfo~3.20.2~37.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-debuginfo-32bit", rpm:"libfreebl3-debuginfo-32bit~3.20.2~37.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-hmac", rpm:"libfreebl3-hmac~3.20.2~37.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreebl3-hmac-32bit", rpm:"libfreebl3-hmac-32bit~3.20.2~37.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3", rpm:"libsoftokn3~3.20.2~37.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-32bit", rpm:"libsoftokn3-32bit~3.20.2~37.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-debuginfo", rpm:"libsoftokn3-debuginfo~3.20.2~37.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-debuginfo-32bit", rpm:"libsoftokn3-debuginfo-32bit~3.20.2~37.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-hmac", rpm:"libsoftokn3-hmac~3.20.2~37.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoftokn3-hmac-32bit", rpm:"libsoftokn3-hmac-32bit~3.20.2~37.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.20.2~37.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.20.2~37.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs", rpm:"mozilla-nss-certs~3.20.2~37.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-32bit", rpm:"mozilla-nss-certs-32bit~3.20.2~37.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo", rpm:"mozilla-nss-certs-debuginfo~3.20.2~37.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo-32bit", rpm:"mozilla-nss-certs-debuginfo-32bit~3.20.2~37.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debuginfo", rpm:"mozilla-nss-debuginfo~3.20.2~37.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debuginfo-32bit", rpm:"mozilla-nss-debuginfo-32bit~3.20.2~37.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-debugsource", rpm:"mozilla-nss-debugsource~3.20.2~37.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit", rpm:"mozilla-nss-sysinit~3.20.2~37.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-32bit", rpm:"mozilla-nss-sysinit-32bit~3.20.2~37.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo", rpm:"mozilla-nss-sysinit-debuginfo~3.20.2~37.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo-32bit", rpm:"mozilla-nss-sysinit-debuginfo-32bit~3.20.2~37.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.20.2~37.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mozilla-nss-tools-debuginfo", rpm:"mozilla-nss-tools-debuginfo~3.20.2~37.1", rls:"SLES12.0SP1"))) {
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
