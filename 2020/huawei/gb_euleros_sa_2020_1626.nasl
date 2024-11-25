# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1626");
  script_cve_id("CVE-2013-4545", "CVE-2013-6422", "CVE-2014-0139", "CVE-2016-3739", "CVE-2018-16840", "CVE-2019-15601");
  script_tag(name:"creation_date", value:"2020-06-16 05:47:13 +0000 (Tue, 16 Jun 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-07 16:17:01 +0000 (Fri, 07 Dec 2018)");

  script_name("Huawei EulerOS: Security Advisory for curl (EulerOS-SA-2020-1626)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1626");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2020-1626");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'curl' package(s) announced via the EulerOS-SA-2020-1626 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A heap use-after-free flaw was found in curl versions from 7.59.0 through 7.61.1 in the code related to closing an easy handle. When closing and cleaning up an 'easy' handle in the `Curl_close()` function, the library code first frees a struct (without nulling the pointer) and might then subsequently erroneously write to a struct field within that already freed struct.(CVE-2018-16840)

CURL before 7.68.0 lacks proper input validation, which allows users to create a `FILE:` URL that can make the client access a remote file using SMB (Windows-only issue).(CVE-2019-15601)

cURL and libcurl 7.18.0 through 7.32.0, when built with OpenSSL, disables the certificate CN and SAN name field verification (CURLOPT_SSL_VERIFYHOST) when the digital signature verification (CURLOPT_SSL_VERIFYPEER) is disabled, which allows man-in-the-middle attackers to spoof SSL servers via an arbitrary valid certificate.(CVE-2013-4545)

The GnuTLS backend in libcurl 7.21.4 through 7.33.0, when disabling digital signature verification (CURLOPT_SSL_VERIFYPEER), also disables the CURLOPT_SSL_VERIFYHOST check for CN or SAN host name fields, which makes it easier for remote attackers to spoof servers and conduct man-in-the-middle (MITM) attacks.(CVE-2013-6422)

cURL and libcurl 7.1 before 7.36.0, when using the OpenSSL, axtls, qsossl or gskit libraries for TLS, recognize a wildcard IP address in the subject's Common Name (CN) field of an X.509 certificate, which might allow man-in-the-middle attackers to spoof arbitrary SSL servers via a crafted certificate issued by a legitimate Certification Authority.(CVE-2014-0139)

The (1) mbed_connect_step1 function in lib/vtls/mbedtls.c and (2) polarssl_connect_step1 function in lib/vtls/polarssl.c in cURL and libcurl before 7.49.0, when using SSLv3 or making a TLS connection to a URL that uses a numerical IP address, allow remote attackers to spoof servers via an arbitrary valid certificate.(CVE-2016-3739)");

  script_tag(name:"affected", value:"'curl' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.29.0~35.h34", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl", rpm:"libcurl~7.29.0~35.h34", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl-devel", rpm:"libcurl-devel~7.29.0~35.h34", rls:"EULEROS-2.0SP2"))) {
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
