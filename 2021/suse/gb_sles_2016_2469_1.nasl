# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2469.1");
  script_cve_id("CVE-2016-2177", "CVE-2016-2178", "CVE-2016-2179", "CVE-2016-2180", "CVE-2016-2181", "CVE-2016-2182", "CVE-2016-2183", "CVE-2016-6302", "CVE-2016-6303", "CVE-2016-6304", "CVE-2016-6306");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:04 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-16 13:18:00 +0000 (Tue, 16 Aug 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2469-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2469-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162469-1/");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20160922.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl1' package(s) announced via the SUSE-SU-2016:2469-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssl1 fixes the following issues:
penSSL Security Advisory [22 Sep 2016] (bsc#999665)
Severity: High
* OCSP Status Request extension unbounded memory growth (CVE-2016-6304)
 (bsc#999666)
Severity: Low
* Pointer arithmetic undefined behaviour (CVE-2016-2177) (bsc#982575)
* Constant time flag not preserved in DSA signing (CVE-2016-2178)
 (bsc#983249)
* DTLS buffered message DoS (CVE-2016-2179) (bsc#994844)
* OOB read in TS_OBJ_print_bio() (CVE-2016-2180) (bsc#990419)
* DTLS replay protection DoS (CVE-2016-2181) (bsc#994749)
* OOB write in BN_bn2dec() (CVE-2016-2182) (bsc#993819)
* Birthday attack against 64-bit block ciphers (SWEET32) (CVE-2016-2183)
 (bsc#995359)
* Malformed SHA512 ticket DoS (CVE-2016-6302) (bsc#995324)
* OOB write in MDC2_Update() (CVE-2016-6303) (bsc#995377)
* Certificate message OOB reads (CVE-2016-6306) (bsc#999668)
More information can be found on:
[link moved to references] Also following bugs were fixed:
* update expired S/MIME certs (bsc#979475)
* improve s390x performance (bsc#982745)
* fix crash in print_notice (bsc#998190)
* resume reading from /dev/urandom when interrupted by a signal
 (bsc#995075)");

  script_tag(name:"affected", value:"'openssl1' package(s) on SUSE Linux Enterprise Server 11.");

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

if(release == "SLES11.0") {

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1-devel", rpm:"libopenssl1-devel~1.0.1g~0.52.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0", rpm:"libopenssl1_0_0~1.0.1g~0.52.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-32bit", rpm:"libopenssl1_0_0-32bit~1.0.1g~0.52.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-x86", rpm:"libopenssl1_0_0-x86~1.0.1g~0.52.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl1", rpm:"openssl1~1.0.1g~0.52.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl1-doc", rpm:"openssl1-doc~1.0.1g~0.52.1", rls:"SLES11.0"))) {
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
