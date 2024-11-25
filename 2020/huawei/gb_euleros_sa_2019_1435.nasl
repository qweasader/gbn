# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.1435");
  script_cve_id("CVE-2013-0179", "CVE-2013-7239", "CVE-2013-7290", "CVE-2013-7291", "CVE-2016-8704", "CVE-2016-8705", "CVE-2016-8706", "CVE-2018-1000127");
  script_tag(name:"creation_date", value:"2020-01-23 11:46:30 +0000 (Thu, 23 Jan 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-10 15:42:19 +0000 (Tue, 10 Jan 2017)");

  script_name("Huawei EulerOS: Security Advisory for memcached (EulerOS-SA-2019-1435)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-3\.0\.1\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-1435");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2019-1435");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'memcached' package(s) announced via the EulerOS-SA-2019-1435 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"memcached before 1.4.17, when running in verbose mode, allows remote attackers to cause a denial of service (crash) via a request that triggers an 'unbounded key print' during logging, related to an issue that was 'quickly grepped out of the source tree' a different vulnerability than CVE-2013-0179 and CVE-2013-7290.(CVE-2013-7291)

An integer overflow flaw, leading to a heap-based buffer overflow, was found in memcached's parsing of SASL authentication messages. An attacker could create a specially crafted message that would cause the memcached server to crash or, potentially, execute arbitrary code.(CVE-2016-8706)

An integer overflow flaw, leading to a heap-based buffer overflow, was found in the memcached binary protocol. An attacker could create a specially crafted message that would cause the memcached server to crash or, potentially, execute arbitrary code.(CVE-2016-8704)

The process_bin_delete function in memcached.c in memcached 1.4.4 and other versions before 1.4.17, when running in verbose mode, allows remote attackers to cause a denial of service (segmentation fault) via a request to delete a key, which does not account for the lack of a null terminator in the key and triggers a buffer over-read when printing to stderr.(CVE-2013-0179)

An integer overflow flaw, leading to a heap-based buffer overflow, was found in the memcached binary protocol. An attacker could create a specially crafted message that would cause the memcached server to crash or, potentially, execute arbitrary code.(CVE-2016-8705)

memcached version prior to 1.4.37 contains an Integer Overflow vulnerability in items.c:item_free() that can result in data corruption and deadlocks due to items existing in hash table being reused from free list. This attack appear to be exploitable via network connectivity to the memcached service. This vulnerability appears to have been fixed in 1.4.37 and later.(CVE-2018-1000127)

memcached before 1.4.17 allows remote attackers to bypass authentication by sending an invalid request with SASL credentials, then sending another request with incorrect SASL credentials.(CVE-2013-7239)

The do_item_get function in items.c in memcached 1.4.4 and other versions before 1.4.17, when running in verbose mode, allows remote attackers to cause a denial of service (segmentation fault) via a request to delete a key, which does not account for the lack of a null terminator in the key and triggers a buffer over-read when printing to stderr, a different vulnerability than CVE-2013-0179.(CVE-2013-7290)");

  script_tag(name:"affected", value:"'memcached' package(s) on Huawei EulerOS Virtualization 3.0.1.0.");

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

if(release == "EULEROSVIRT-3.0.1.0") {

  if(!isnull(res = isrpmvuln(pkg:"memcached", rpm:"memcached~1.4.15~10.1.h2.eulerosv2r7", rls:"EULEROSVIRT-3.0.1.0"))) {
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
