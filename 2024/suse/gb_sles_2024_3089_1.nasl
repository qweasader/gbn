# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.3089.1");
  script_cve_id("CVE-2023-45288", "CVE-2023-45289", "CVE-2023-45290", "CVE-2024-24783", "CVE-2024-24784", "CVE-2024-24785", "CVE-2024-24787", "CVE-2024-24789", "CVE-2024-24790", "CVE-2024-24791");
  script_tag(name:"creation_date", value:"2024-09-04 04:26:54 +0000 (Wed, 04 Sep 2024)");
  script_version("2024-09-04T05:16:32+0000");
  script_tag(name:"last_modification", value:"2024-09-04 05:16:32 +0000 (Wed, 04 Sep 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-18 17:59:12 +0000 (Tue, 18 Jun 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:3089-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3089-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20243089-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.21-openssl' package(s) announced via the SUSE-SU-2024:3089-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.21-openssl fixes the following issues:

CVE-2024-24791: Fixed denial of service due to improper 100-continue handling (bsc#1227314)
CVE-2024-24789: Fixed mishandling of corrupt central directory record in archive/zip (bsc#1225973)
CVE-2024-24790: Fixed unexpected behavior from Is methods for IPv4-mapped IPv6 addresses in net/netip (bsc#1225974)
CVE-2024-24787: Fixed arbitrary code execution during build on darwin in cmd/go (bsc#1224017)
CVE-2023-45288: Fixed denial of service due to close connections when receiving too many headers in net/http and x/net/http2 (bsc#1221400)
CVE-2023-45289: Fixed incorrect forwarding of sensitive headers and cookies on HTTP redirect in net/http and net/http/cookiejar (bsc#1221000)
CVE-2023-45290: Fixed memory exhaustion in Request.ParseMultipartForm in net/http (bsc#1221001)
CVE-2024-24783: Fixed denial of service on certificates with an unknown public key algorithm in crypto/x509 (bsc#1220999)
CVE-2024-24784: Fixed comments in display names are incorrectly handled in net/mail (bsc#1221002)
CVE-2024-24785: Fixed errors returned from MarshalJSON methods may break template escaping in html/template (bsc#1221003)

Other fixes:
- Update to version 1.21.13.1 cut from the go1.21-fips-release (jsc#SLE-18320)
- Update to version 1.21.13 (bsc#1212475)
- Remove subpackage go1.x-openssl-libstd for compiled shared object libstd.so. (jsc#PED-1962)
- Ensure VERSION file is present in GOROOT as required by go tool dist and go tool distpack (bsc#1219988)");

  script_tag(name:"affected", value:"'go1.21-openssl' package(s) on SUSE Linux Enterprise Desktop 15-SP4, SUSE Linux Enterprise High Performance Computing 15-SP4, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"go1.21-openssl", rpm:"go1.21-openssl~1.21.13.1~150000.1.11.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.21-openssl-doc", rpm:"go1.21-openssl-doc~1.21.13.1~150000.1.11.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.21-openssl-race", rpm:"go1.21-openssl-race~1.21.13.1~150000.1.11.1", rls:"SLES15.0SP4"))) {
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
