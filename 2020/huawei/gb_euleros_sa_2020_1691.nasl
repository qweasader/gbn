# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1691");
  script_cve_id("CVE-2020-10663", "CVE-2020-10933");
  script_tag(name:"creation_date", value:"2020-06-26 07:26:53 +0000 (Fri, 26 Jun 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-08 15:37:13 +0000 (Fri, 08 May 2020)");

  script_name("Huawei EulerOS: Security Advisory for ruby (EulerOS-SA-2020-1691)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.6\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1691");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2020-1691");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'ruby' package(s) announced via the EulerOS-SA-2020-1691 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in Ruby 2.5.x through 2.5.7, 2.6.x through 2.6.5, and 2.7.0. If a victim calls BasicSocket#read_nonblock(requested_size, buffer, exception: false), the method resizes the buffer to fit the requested size, but no data is copied. Thus, the buffer string provides the previous value of the heap. This may expose possibly sensitive data from the interpreter.(CVE-2020-10933)

The JSON gem through 2.2.0 for Ruby, as used in Ruby 2.4 through 2.4.9, 2.5 through 2.5.7, and 2.6 through 2.6.5, has an Unsafe Object Creation Vulnerability. This is quite similar to CVE-2013-0269, but does not rely on poor garbage-collection behavior within Ruby. Specifically, use of JSON parsing methods can lead to creation of a malicious object within the interpreter, with adverse effects that are application-dependent.(CVE-2020-10663)");

  script_tag(name:"affected", value:"'ruby' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.6.0.");

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

if(release == "EULEROSVIRTARM64-3.0.6.0") {

  if(!isnull(res = isrpmvuln(pkg:"ruby", rpm:"ruby~2.5.1~98.h8.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-irb", rpm:"ruby-irb~2.5.1~98.h8.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-libs", rpm:"ruby-libs~2.5.1~98.h8.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-bigdecimal", rpm:"rubygem-bigdecimal~1.3.4~98.h8.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-io-console", rpm:"rubygem-io-console~0.4.6~98.h8.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-json", rpm:"rubygem-json~2.1.0~98.h8.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-openssl", rpm:"rubygem-openssl~2.1.0~98.h8.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-psych", rpm:"rubygem-psych~3.0.2~98.h8.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-rdoc", rpm:"rubygem-rdoc~6.0.1~98.h8.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygems", rpm:"rubygems~2.7.6~98.h8.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
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
