# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856150");
  script_version("2024-06-07T15:38:39+0000");
  script_cve_id("CVE-2024-29040");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-06-07 15:38:39 +0000 (Fri, 07 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-05-24 01:00:32 +0000 (Fri, 24 May 2024)");
  script_name("openSUSE: Security Advisory for tpm2 (SUSE-SU-2024:1635-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5|openSUSELeapMicro5\.3|openSUSELeapMicro5\.4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1635-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/52Q2PPFE6YGT77VNPQKJDXJVARKPOPKQ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tpm2'
  package(s) announced via the SUSE-SU-2024:1635-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tpm2-0-tss fixes the following issues:

  * CVE-2024-29040: Fixed quote data validation by Fapi_VerifyQuote
      (bsc#1223690).

  ##");

  script_tag(name:"affected", value:"'tpm2' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5, openSUSE Leap Micro 5.3, openSUSE Leap Micro 5.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys1-debuginfo", rpm:"libtss2-sys1-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2-0-tss-devel", rpm:"tpm2-0-tss-devel~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-swtpm0-debuginfo", rpm:"libtss2-tcti-swtpm0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0", rpm:"libtss2-tcti-mssim0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2-0-tss", rpm:"tpm2-0-tss~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tctildr0", rpm:"libtss2-tctildr0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2-0-tss-debugsource", rpm:"tpm2-0-tss-debugsource~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tctildr0-debuginfo", rpm:"libtss2-tctildr0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0-debuginfo", rpm:"libtss2-esys0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0", rpm:"libtss2-tcti-device0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0", rpm:"libtss2-esys0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-rc0", rpm:"libtss2-rc0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-cmd0", rpm:"libtss2-tcti-cmd0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-pcap0", rpm:"libtss2-tcti-pcap0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-swtpm0", rpm:"libtss2-tcti-swtpm0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-fapi1-debuginfo", rpm:"libtss2-fapi1-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-rc0-debuginfo", rpm:"libtss2-rc0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0", rpm:"libtss2-mu0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0-debuginfo", rpm:"libtss2-mu0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-cmd0-debuginfo", rpm:"libtss2-tcti-cmd0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0-debuginfo", rpm:"libtss2-tcti-mssim0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys1", rpm:"libtss2-sys1~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-fapi1", rpm:"libtss2-fapi1~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0-debuginfo", rpm:"libtss2-tcti-device0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-pcap0-debuginfo", rpm:"libtss2-tcti-pcap0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-rc0-32bit", rpm:"libtss2-rc0-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0-32bit-debuginfo", rpm:"libtss2-esys0-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys1-32bit", rpm:"libtss2-sys1-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-rc0-32bit-debuginfo", rpm:"libtss2-rc0-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-fapi1-32bit-debuginfo", rpm:"libtss2-fapi1-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0-32bit-debuginfo", rpm:"libtss2-tcti-mssim0-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-fapi1-32bit", rpm:"libtss2-fapi1-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-swtpm0-32bit-debuginfo", rpm:"libtss2-tcti-swtpm0-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-swtpm0-32bit", rpm:"libtss2-tcti-swtpm0-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tctildr0-32bit-debuginfo", rpm:"libtss2-tctildr0-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0-32bit", rpm:"libtss2-mu0-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0-32bit-debuginfo", rpm:"libtss2-tcti-device0-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0-32bit", rpm:"libtss2-tcti-device0-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0-32bit-debuginfo", rpm:"libtss2-mu0-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-cmd0-32bit", rpm:"libtss2-tcti-cmd0-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0-32bit", rpm:"libtss2-esys0-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-cmd0-32bit-debuginfo", rpm:"libtss2-tcti-cmd0-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys1-32bit-debuginfo", rpm:"libtss2-sys1-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tctildr0-32bit", rpm:"libtss2-tctildr0-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0-32bit", rpm:"libtss2-tcti-mssim0-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-rc0-64bit-debuginfo", rpm:"libtss2-rc0-64bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0-64bit-debuginfo", rpm:"libtss2-tcti-device0-64bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0-64bit-debuginfo", rpm:"libtss2-mu0-64bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-swtpm0-64bit-debuginfo", rpm:"libtss2-tcti-swtpm0-64bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-cmd0-64bit-debuginfo", rpm:"libtss2-tcti-cmd0-64bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0-64bit", rpm:"libtss2-esys0-64bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tctildr0-64bit-debuginfo", rpm:"libtss2-tctildr0-64bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-fapi1-64bit-debuginfo", rpm:"libtss2-fapi1-64bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0-64bit", rpm:"libtss2-tcti-mssim0-64bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tctildr0-64bit", rpm:"libtss2-tctildr0-64bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-cmd0-64bit", rpm:"libtss2-tcti-cmd0-64bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0-64bit-debuginfo", rpm:"libtss2-tcti-mssim0-64bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-swtpm0-64bit", rpm:"libtss2-tcti-swtpm0-64bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0-64bit-debuginfo", rpm:"libtss2-esys0-64bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-fapi1-64bit", rpm:"libtss2-fapi1-64bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-rc0-64bit", rpm:"libtss2-rc0-64bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0-64bit", rpm:"libtss2-mu0-64bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys1-64bit-debuginfo", rpm:"libtss2-sys1-64bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0-64bit", rpm:"libtss2-tcti-device0-64bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys1-64bit", rpm:"libtss2-sys1-64bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys1-debuginfo", rpm:"libtss2-sys1-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2-0-tss-devel", rpm:"tpm2-0-tss-devel~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-swtpm0-debuginfo", rpm:"libtss2-tcti-swtpm0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0", rpm:"libtss2-tcti-mssim0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2-0-tss", rpm:"tpm2-0-tss~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tctildr0", rpm:"libtss2-tctildr0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2-0-tss-debugsource", rpm:"tpm2-0-tss-debugsource~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tctildr0-debuginfo", rpm:"libtss2-tctildr0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0-debuginfo", rpm:"libtss2-esys0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0", rpm:"libtss2-tcti-device0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0", rpm:"libtss2-esys0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-rc0", rpm:"libtss2-rc0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-cmd0", rpm:"libtss2-tcti-cmd0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-pcap0", rpm:"libtss2-tcti-pcap0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-swtpm0", rpm:"libtss2-tcti-swtpm0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-fapi1-debuginfo", rpm:"libtss2-fapi1-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-rc0-debuginfo", rpm:"libtss2-rc0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0", rpm:"libtss2-mu0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0-debuginfo", rpm:"libtss2-mu0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-cmd0-debuginfo", rpm:"libtss2-tcti-cmd0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0-debuginfo", rpm:"libtss2-tcti-mssim0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys1", rpm:"libtss2-sys1~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-fapi1", rpm:"libtss2-fapi1~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0-debuginfo", rpm:"libtss2-tcti-device0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-pcap0-debuginfo", rpm:"libtss2-tcti-pcap0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-rc0-32bit", rpm:"libtss2-rc0-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0-32bit-debuginfo", rpm:"libtss2-esys0-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys1-32bit", rpm:"libtss2-sys1-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-rc0-32bit-debuginfo", rpm:"libtss2-rc0-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-fapi1-32bit-debuginfo", rpm:"libtss2-fapi1-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0-32bit-debuginfo", rpm:"libtss2-tcti-mssim0-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-fapi1-32bit", rpm:"libtss2-fapi1-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-swtpm0-32bit-debuginfo", rpm:"libtss2-tcti-swtpm0-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-swtpm0-32bit", rpm:"libtss2-tcti-swtpm0-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tctildr0-32bit-debuginfo", rpm:"libtss2-tctildr0-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0-32bit", rpm:"libtss2-mu0-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0-32bit-debuginfo", rpm:"libtss2-tcti-device0-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0-32bit", rpm:"libtss2-tcti-device0-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0-32bit-debuginfo", rpm:"libtss2-mu0-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-cmd0-32bit", rpm:"libtss2-tcti-cmd0-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0-32bit", rpm:"libtss2-esys0-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-cmd0-32bit-debuginfo", rpm:"libtss2-tcti-cmd0-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys1-32bit-debuginfo", rpm:"libtss2-sys1-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tctildr0-32bit", rpm:"libtss2-tctildr0-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0-32bit", rpm:"libtss2-tcti-mssim0-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-rc0-64bit-debuginfo", rpm:"libtss2-rc0-64bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0-64bit-debuginfo", rpm:"libtss2-tcti-device0-64bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0-64bit-debuginfo", rpm:"libtss2-mu0-64bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-swtpm0-64bit-debuginfo", rpm:"libtss2-tcti-swtpm0-64bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-cmd0-64bit-debuginfo", rpm:"libtss2-tcti-cmd0-64bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0-64bit", rpm:"libtss2-esys0-64bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tctildr0-64bit-debuginfo", rpm:"libtss2-tctildr0-64bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-fapi1-64bit-debuginfo", rpm:"libtss2-fapi1-64bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0-64bit", rpm:"libtss2-tcti-mssim0-64bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tctildr0-64bit", rpm:"libtss2-tctildr0-64bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-cmd0-64bit", rpm:"libtss2-tcti-cmd0-64bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0-64bit-debuginfo", rpm:"libtss2-tcti-mssim0-64bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-swtpm0-64bit", rpm:"libtss2-tcti-swtpm0-64bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0-64bit-debuginfo", rpm:"libtss2-esys0-64bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-fapi1-64bit", rpm:"libtss2-fapi1-64bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-rc0-64bit", rpm:"libtss2-rc0-64bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0-64bit", rpm:"libtss2-mu0-64bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys1-64bit-debuginfo", rpm:"libtss2-sys1-64bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0-64bit", rpm:"libtss2-tcti-device0-64bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys1-64bit", rpm:"libtss2-sys1-64bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys1-debuginfo", rpm:"libtss2-sys1-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2-0-tss-devel", rpm:"tpm2-0-tss-devel~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-swtpm0-debuginfo", rpm:"libtss2-tcti-swtpm0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0", rpm:"libtss2-tcti-mssim0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2-0-tss", rpm:"tpm2-0-tss~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tctildr0", rpm:"libtss2-tctildr0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2-0-tss-debugsource", rpm:"tpm2-0-tss-debugsource~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tctildr0-debuginfo", rpm:"libtss2-tctildr0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0-debuginfo", rpm:"libtss2-esys0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0", rpm:"libtss2-tcti-device0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0", rpm:"libtss2-esys0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-rc0", rpm:"libtss2-rc0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-cmd0", rpm:"libtss2-tcti-cmd0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-pcap0", rpm:"libtss2-tcti-pcap0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-swtpm0", rpm:"libtss2-tcti-swtpm0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-fapi1-debuginfo", rpm:"libtss2-fapi1-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-rc0-debuginfo", rpm:"libtss2-rc0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0", rpm:"libtss2-mu0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0-debuginfo", rpm:"libtss2-mu0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-cmd0-debuginfo", rpm:"libtss2-tcti-cmd0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0-debuginfo", rpm:"libtss2-tcti-mssim0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys1", rpm:"libtss2-sys1~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-fapi1", rpm:"libtss2-fapi1~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0-debuginfo", rpm:"libtss2-tcti-device0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-pcap0-debuginfo", rpm:"libtss2-tcti-pcap0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-rc0-32bit", rpm:"libtss2-rc0-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0-32bit-debuginfo", rpm:"libtss2-esys0-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys1-32bit", rpm:"libtss2-sys1-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-rc0-32bit-debuginfo", rpm:"libtss2-rc0-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-fapi1-32bit-debuginfo", rpm:"libtss2-fapi1-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0-32bit-debuginfo", rpm:"libtss2-tcti-mssim0-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-fapi1-32bit", rpm:"libtss2-fapi1-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-swtpm0-32bit-debuginfo", rpm:"libtss2-tcti-swtpm0-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-swtpm0-32bit", rpm:"libtss2-tcti-swtpm0-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tctildr0-32bit-debuginfo", rpm:"libtss2-tctildr0-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0-32bit", rpm:"libtss2-mu0-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0-32bit-debuginfo", rpm:"libtss2-tcti-device0-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0-32bit", rpm:"libtss2-tcti-device0-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0-32bit-debuginfo", rpm:"libtss2-mu0-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-cmd0-32bit", rpm:"libtss2-tcti-cmd0-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0-32bit", rpm:"libtss2-esys0-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-cmd0-32bit-debuginfo", rpm:"libtss2-tcti-cmd0-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys1-32bit-debuginfo", rpm:"libtss2-sys1-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tctildr0-32bit", rpm:"libtss2-tctildr0-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0-32bit", rpm:"libtss2-tcti-mssim0-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys1-debuginfo", rpm:"libtss2-sys1-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2-0-tss-devel", rpm:"tpm2-0-tss-devel~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-swtpm0-debuginfo", rpm:"libtss2-tcti-swtpm0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0", rpm:"libtss2-tcti-mssim0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2-0-tss", rpm:"tpm2-0-tss~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tctildr0", rpm:"libtss2-tctildr0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2-0-tss-debugsource", rpm:"tpm2-0-tss-debugsource~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tctildr0-debuginfo", rpm:"libtss2-tctildr0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0-debuginfo", rpm:"libtss2-esys0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0", rpm:"libtss2-tcti-device0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0", rpm:"libtss2-esys0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-rc0", rpm:"libtss2-rc0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-cmd0", rpm:"libtss2-tcti-cmd0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-pcap0", rpm:"libtss2-tcti-pcap0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-swtpm0", rpm:"libtss2-tcti-swtpm0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-fapi1-debuginfo", rpm:"libtss2-fapi1-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-rc0-debuginfo", rpm:"libtss2-rc0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0", rpm:"libtss2-mu0~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0-debuginfo", rpm:"libtss2-mu0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-cmd0-debuginfo", rpm:"libtss2-tcti-cmd0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0-debuginfo", rpm:"libtss2-tcti-mssim0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys1", rpm:"libtss2-sys1~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-fapi1", rpm:"libtss2-fapi1~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0-debuginfo", rpm:"libtss2-tcti-device0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-pcap0-debuginfo", rpm:"libtss2-tcti-pcap0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-rc0-32bit", rpm:"libtss2-rc0-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0-32bit-debuginfo", rpm:"libtss2-esys0-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys1-32bit", rpm:"libtss2-sys1-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-rc0-32bit-debuginfo", rpm:"libtss2-rc0-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-fapi1-32bit-debuginfo", rpm:"libtss2-fapi1-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0-32bit-debuginfo", rpm:"libtss2-tcti-mssim0-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-fapi1-32bit", rpm:"libtss2-fapi1-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-swtpm0-32bit-debuginfo", rpm:"libtss2-tcti-swtpm0-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-swtpm0-32bit", rpm:"libtss2-tcti-swtpm0-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tctildr0-32bit-debuginfo", rpm:"libtss2-tctildr0-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0-32bit", rpm:"libtss2-mu0-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0-32bit-debuginfo", rpm:"libtss2-tcti-device0-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0-32bit", rpm:"libtss2-tcti-device0-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0-32bit-debuginfo", rpm:"libtss2-mu0-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-cmd0-32bit", rpm:"libtss2-tcti-cmd0-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0-32bit", rpm:"libtss2-esys0-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-cmd0-32bit-debuginfo", rpm:"libtss2-tcti-cmd0-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys1-32bit-debuginfo", rpm:"libtss2-sys1-32bit-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tctildr0-32bit", rpm:"libtss2-tctildr0-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-mssim0-32bit", rpm:"libtss2-tcti-mssim0-32bit~3.1.0~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.3") {

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0-debuginfo", rpm:"libtss2-mu0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys1", rpm:"libtss2-sys1~3.1.0~150400.3.6.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tctildr0", rpm:"libtss2-tctildr0~3.1.0~150400.3.6.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2-0-tss-debugsource", rpm:"tpm2-0-tss-debugsource~3.1.0~150400.3.6.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-rc0-debuginfo", rpm:"libtss2-rc0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tctildr0-debuginfo", rpm:"libtss2-tctildr0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0-debuginfo", rpm:"libtss2-esys0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-fapi1", rpm:"libtss2-fapi1~3.1.0~150400.3.6.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0", rpm:"libtss2-tcti-device0~3.1.0~150400.3.6.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0", rpm:"libtss2-esys0~3.1.0~150400.3.6.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys1-debuginfo", rpm:"libtss2-sys1-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0", rpm:"libtss2-mu0~3.1.0~150400.3.6.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-rc0", rpm:"libtss2-rc0~3.1.0~150400.3.6.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0-debuginfo", rpm:"libtss2-tcti-device0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-fapi1-debuginfo", rpm:"libtss2-fapi1-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2-0-tss", rpm:"tpm2-0-tss~3.1.0~150400.3.6.1", rls:"openSUSELeapMicro5.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeapMicro5.4") {

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0-debuginfo", rpm:"libtss2-mu0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys1", rpm:"libtss2-sys1~3.1.0~150400.3.6.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tctildr0", rpm:"libtss2-tctildr0~3.1.0~150400.3.6.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2-0-tss-debugsource", rpm:"tpm2-0-tss-debugsource~3.1.0~150400.3.6.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-rc0-debuginfo", rpm:"libtss2-rc0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tctildr0-debuginfo", rpm:"libtss2-tctildr0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0-debuginfo", rpm:"libtss2-esys0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-fapi1", rpm:"libtss2-fapi1~3.1.0~150400.3.6.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0", rpm:"libtss2-tcti-device0~3.1.0~150400.3.6.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-esys0", rpm:"libtss2-esys0~3.1.0~150400.3.6.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-sys1-debuginfo", rpm:"libtss2-sys1-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-mu0", rpm:"libtss2-mu0~3.1.0~150400.3.6.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-rc0", rpm:"libtss2-rc0~3.1.0~150400.3.6.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-tcti-device0-debuginfo", rpm:"libtss2-tcti-device0-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtss2-fapi1-debuginfo", rpm:"libtss2-fapi1-debuginfo~3.1.0~150400.3.6.1", rls:"openSUSELeapMicro5.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tpm2-0-tss", rpm:"tpm2-0-tss~3.1.0~150400.3.6.1", rls:"openSUSELeapMicro5.4"))) {
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
