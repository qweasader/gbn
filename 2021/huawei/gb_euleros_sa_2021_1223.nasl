# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1223");
  script_cve_id("CVE-2016-1246", "CVE-2016-1249", "CVE-2017-10788", "CVE-2017-10789");
  script_tag(name:"creation_date", value:"2021-02-05 15:04:11 +0000 (Fri, 05 Feb 2021)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-12 18:24:31 +0000 (Wed, 12 Jul 2017)");

  script_name("Huawei EulerOS: Security Advisory for perl-DBD-MySQL (EulerOS-SA-2021-1223)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP5");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1223");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2021-1223");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'perl-DBD-MySQL' package(s) announced via the EulerOS-SA-2021-1223 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Buffer overflow in the DBD::mysql module before 4.037 for Perl allows context-dependent attackers to cause a denial of service (crash) via vectors related to an error message.(CVE-2016-1246)

The DBD::mysql module through 4.043 for Perl allows remote attackers to cause a denial of service (use-after-free and application crash) or possibly have unspecified other impact by triggering (1) certain error responses from a MySQL server or (2) a loss of a network connection to a MySQL server. The use-after-free defect was introduced by relying on incorrect Oracle mysql_stmt_close documentation and code examples.(CVE-2017-10788)

The DBD::mysql module before 4.039 for Perl, when using server-side prepared statement support, allows attackers to cause a denial of service (out-of-bounds read) via vectors involving an unaligned number of placeholders in WHERE condition and output fields in SELECT expression.(CVE-2016-1249)

The DBD::mysql module through 4.043 for Perl uses the mysql_ssl=1 setting to mean that SSL is optional (even though this setting's documentation has a 'your communication with the server will be encrypted' statement), which allows man-in-the-middle attackers to spoof servers via a cleartext-downgrade attack, a related issue to CVE-2015-3152.(CVE-2017-10789)");

  script_tag(name:"affected", value:"'perl-DBD-MySQL' package(s) on Huawei EulerOS V2.0SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"perl-DBD-MySQL", rpm:"perl-DBD-MySQL~4.023~6.h2.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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
