# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.2140");
  script_cve_id("CVE-2018-16741", "CVE-2018-16744", "CVE-2018-16745");
  script_tag(name:"creation_date", value:"2020-09-29 13:47:56 +0000 (Tue, 29 Sep 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Huawei EulerOS: Security Advisory for mgetty (EulerOS-SA-2020-2140)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP3");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-2140");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2140");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'mgetty' package(s) announced via the EulerOS-SA-2020-2140 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in mgetty before 1.2.1. In fax/faxq-helper.c, the function do_activate() does not properly sanitize shell metacharacters to prevent command injection. It is possible to use the <pipe><pipe>, &&, or > characters within a file created by the 'faxq-helper activate ' command.(CVE-2018-16741)

An issue was discovered in mgetty before 1.2.1. In fax_notify_mail() in faxrec.c, the mail_to parameter is not sanitized. It could allow for command injection if untrusted input can reach it, because popen is used.(CVE-2018-16744)

An issue was discovered in mgetty before 1.2.1. In fax_notify_mail() in faxrec.c, the mail_to parameter is not sanitized. It could allow a buffer overflow if long untrusted input can reach it.(CVE-2018-16745)");

  script_tag(name:"affected", value:"'mgetty' package(s) on Huawei EulerOS V2.0SP3.");

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

if(release == "EULEROS-2.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"mgetty", rpm:"mgetty~1.1.36~28.h1", rls:"EULEROS-2.0SP3"))) {
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
