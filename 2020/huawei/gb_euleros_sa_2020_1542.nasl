# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1542");
  script_cve_id("CVE-2016-10397", "CVE-2016-7412", "CVE-2017-11145", "CVE-2017-16642", "CVE-2017-7189", "CVE-2017-7272", "CVE-2019-11047", "CVE-2019-11050", "CVE-2019-19204", "CVE-2019-19246");
  script_tag(name:"creation_date", value:"2020-04-30 12:13:02 +0000 (Thu, 30 Apr 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-09-19 14:28:21 +0000 (Mon, 19 Sep 2016)");

  script_name("Huawei EulerOS: Security Advisory for php (EulerOS-SA-2020-1542)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.2\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1542");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2020-1542");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'php' package(s) announced via the EulerOS-SA-2020-1542 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in HAProxy before 2.0.6. In legacy mode, messages featuring a transfer-encoding header missing the 'chunked' value were not being correctly rejected. The impact was limited but if combined with the 'http-reuse always' setting, it could be used to help construct an HTTP request smuggling attack against a vulnerable component employing a lenient parser that would ignore the content-length header as soon as it saw a transfer-encoding one (even if not entirely valid according to the specification).(CVE-2017-16642)

In PHP before 5.6.32, 7.x before 7.0.25, and 7.1.x before 7.1.11, an error in the date extension's timelib_meridian handling of 'front of' and 'back of' directives could be used by attackers able to supply date strings to leak information from the interpreter, related to ext/date/lib/parse_date.c out-of-bounds reads affecting the php_parse_date function. NOTE: this is a different issue than CVE-2017-11145.(CVE-2017-11145)

ext/standard/var_unserializer.re in PHP before 5.6.26 mishandles object-deserialization failures, which allows remote attackers to cause a denial of service (memory corruption) or possibly have unspecified other impact via an unserialize call that references a partially constructed object.(CVE-2016-10397)

Double free vulnerability in the zend_ts_hash_graceful_destroy function in zend_ts_hash.c in the Zend Engine in PHP through 5.5.20 and 5.6.x through 5.6.4 allows remote attackers to cause a denial of service or possibly have unspecified other impact via unknown vectors.(CVE-2016-7412)

Oniguruma through 6.9.3, as used in PHP 7.3.x and other products, has a heap-based buffer over-read in str_lower_case_match in regexec.c.(CVE-2019-19246)

When PHP EXIF extension is parsing EXIF information from an image, e.g. via exif_read_data() function, in PHP versions 7.2.x below 7.2.26, 7.3.x below 7.3.13 and 7.4.0 it is possible to supply it with data what will cause it to read past the allocated buffer. This may lead to information disclosure or crash.(CVE-2019-11047)

main/php_open_temporary_file.c in PHP before 5.5.28 and 5.6.x before 5.6.12 does not ensure thread safety, which allows remote attackers to cause a denial of service (race condition and heap memory corruption) by leveraging an application that performs many temporary-file accesses.(CVE-2017-7272)

When PHP EXIF extension is parsing EXIF information from an image, e.g. via exif_read_data() function, in PHP versions 7.2.x below 7.2.26, 7.3.x below 7.3.13 and 7.4.0 it is possible to supply it with data what will cause it to read past the allocated buffer. This may lead to information disclosure or crash.(CVE-2019-11050)

An issue was discovered in Oniguruma 6.x before 6.9.4_rc2. In the function fetch_interval_quantifier (formerly known as fetch_range_quantifier) in regparse.c, PFETCH is called without checking PEND. This leads to a heap-based buffer ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'php' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.2.0.");

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

if(release == "EULEROSVIRTARM64-3.0.2.0") {

  if(!isnull(res = isrpmvuln(pkg:"php", rpm:"php~5.4.16~45.h29", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-cli", rpm:"php-cli~5.4.16~45.h29", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-common", rpm:"php-common~5.4.16~45.h29", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
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
