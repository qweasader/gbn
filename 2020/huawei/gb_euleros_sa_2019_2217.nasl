# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2217");
  script_cve_id("CVE-2016-0799", "CVE-2016-2105", "CVE-2016-2106", "CVE-2016-2109", "CVE-2016-2842", "CVE-2016-6306");
  script_tag(name:"creation_date", value:"2020-01-23 12:40:17 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-03-04 18:30:22 +0000 (Fri, 04 Mar 2016)");

  script_name("Huawei EulerOS: Security Advisory for openssl098e (EulerOS-SA-2019-2217)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP5");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2217");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-2217");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'openssl098e' package(s) announced via the EulerOS-SA-2019-2217 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An integer overflow flaw, leading to a buffer overflow, was found in the way the EVP_EncodeUpdate() function of OpenSSL parsed very large amounts of input data. A remote attacker could use this flaw to crash an application using OpenSSL or, possibly, execute arbitrary code with the permissions of the user running that application.(CVE-2016-2105)

An integer overflow flaw, leading to a buffer overflow, was found in the way the EVP_EncryptUpdate() function of OpenSSL parsed very large amounts of input data. A remote attacker could use this flaw to crash an application using OpenSSL or, possibly, execute arbitrary code with the permissions of the user running that application.(CVE-2016-2106)

A denial of service flaw was found in the way OpenSSL parsed certain ASN.1-encoded data from BIO (OpenSSL's I/O abstraction) inputs. An application using OpenSSL that accepts untrusted ASN.1 BIO input could be forced to allocate an excessive amount of data.(CVE-2016-2109)

The fmtstr function in crypto/bio/b_print.c in OpenSSL 1.0.1 before 1.0.1s and 1.0.2 before 1.0.2g improperly calculates string lengths, which allows remote attackers to cause a denial of service (overflow and out-of-bounds read) or possibly have unspecified other impact via a long string, as demonstrated by a large amount of ASN.1 data, a different vulnerability than CVE-2016-2842.(CVE-2016-0799)

The certificate parser in OpenSSL before 1.0.1u and 1.0.2 before 1.0.2i might allow remote attackers to cause a denial of service (out-of-bounds read) via crafted certificate operations, related to s3_clnt.c and s3_srvr.c.(CVE-2016-6306)

The doapr_outch function in crypto/bio/b_print.c in OpenSSL 1.0.1 before 1.0.1s and 1.0.2 before 1.0.2g does not verify that a certain memory allocation succeeds, which allows remote attackers to cause a denial of service (out-of-bounds write or memory consumption) or possibly have unspecified other impact via a long string, as demonstrated by a large amount of ASN.1 data, a different vulnerability than CVE-2016-0799.(CVE-2016-2842)");

  script_tag(name:"affected", value:"'openssl098e' package(s) on Huawei EulerOS V2.0SP5.");

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

if(release == "EULEROS-2.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"openssl098e", rpm:"openssl098e~0.9.8e~29.3.h8.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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
