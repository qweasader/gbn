# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1885");
  script_cve_id("CVE-2019-15691", "CVE-2019-15692", "CVE-2019-15693", "CVE-2019-15694", "CVE-2019-15695");
  script_tag(name:"creation_date", value:"2020-08-31 07:04:23 +0000 (Mon, 31 Aug 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-16 20:00:00 +0000 (Fri, 16 Oct 2020)");

  script_name("Huawei EulerOS: Security Advisory for tigervnc (EulerOS-SA-2020-1885)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP8");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1885");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1885");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'tigervnc' package(s) announced via the EulerOS-SA-2020-1885 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"TigerVNC version prior to 1.10.1 is vulnerable to stack use-after-return, which occurs due to incorrect usage of stack memory in ZRLEDecoder. If decoding routine would throw an exception, ZRLEDecoder may try to access stack variable, which has been already freed during the process of stack unwinding. Exploitation of this vulnerability could potentially result into remote code execution. This attack appear to be exploitable via network connectivity.(CVE-2019-15691)

TigerVNC version prior to 1.10.1 is vulnerable to heap buffer overflow. Vulnerability could be triggered from CopyRectDecoder due to incorrect value checks. Exploitation of this vulnerability could potentially result into remote code execution. This attack appear to be exploitable via network connectivity.(CVE-2019-15692)

TigerVNC version prior to 1.10.1 is vulnerable to heap buffer overflow, which occurs in TightDecoder::FilterGradient. Exploitation of this vulnerability could potentially result into remote code execution. This attack appear to be exploitable via network connectivity.(CVE-2019-15693)

TigerVNC version prior to 1.10.1 is vulnerable to heap buffer overflow, which could be triggered from DecodeManager::decodeRect. Vulnerability occurs due to the signdness error in processing MemOutStream. Exploitation of this vulnerability could potentially result into remote code execution. This attack appear to be exploitable via network connectivity.(CVE-2019-15694)

TigerVNC version prior to 1.10.1 is vulnerable to stack buffer overflow, which could be triggered from CMsgReader::readSetCursor. This vulnerability occurs due to insufficient sanitization of PixelFormat. Since remote attacker can choose offset from start of the buffer to start writing his values, exploitation of this vulnerability could potentially result into remote code execution. This attack appear to be exploitable via network connectivity.(CVE-2019-15695)");

  script_tag(name:"affected", value:"'tigervnc' package(s) on Huawei EulerOS V2.0SP8.");

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

if(release == "EULEROS-2.0SP8") {

  if(!isnull(res = isrpmvuln(pkg:"tigervnc", rpm:"tigervnc~1.9.0~3.h1.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc-icons", rpm:"tigervnc-icons~1.9.0~3.h1.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc-license", rpm:"tigervnc-license~1.9.0~3.h1.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc-server", rpm:"tigervnc-server~1.9.0~3.h1.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tigervnc-server-minimal", rpm:"tigervnc-server-minimal~1.9.0~3.h1.eulerosv2r8", rls:"EULEROS-2.0SP8"))) {
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
