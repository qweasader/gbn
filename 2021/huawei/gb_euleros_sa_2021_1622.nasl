# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1622");
  script_cve_id("CVE-2014-10402", "CVE-2019-20919", "CVE-2020-14392", "CVE-2020-14393");
  script_tag(name:"creation_date", value:"2021-03-12 07:23:52 +0000 (Fri, 12 Mar 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-28 16:15:00 +0000 (Mon, 28 Sep 2020)");

  script_name("Huawei EulerOS: Security Advisory for perl-DBI (EulerOS-SA-2021-1622)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.9\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1622");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1622");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'perl-DBI' package(s) announced via the EulerOS-SA-2021-1622 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in the DBI module before 1.643 for Perl. The hv_fetch() documentation requires checking for NULL and the code does that. But, shortly thereafter, it calls SvOK(profile), causing a NULL pointer dereference.(CVE-2019-20919)

An issue was discovered in the DBI module through 1.643 for Perl. DBD::File drivers can open files from folders other than those specifically passed via the f_dir attribute in the data source name (DSN). NOTE: this issue exists because of an incomplete fix for CVE-2014-10401.(CVE-2014-10402)

An untrusted pointer dereference flaw was found in Perl-DBI < 1.643. A local attacker who is able to manipulate calls to dbd_db_login6_sv() could cause memory corruption, affecting the service's availability.(CVE-2020-14392)

A buffer overflow was found in perl-DBI < 1.643 in DBI.xs. A local attacker who is able to supply a string longer than 300 characters could cause an out-of-bounds write, affecting the availability of the service or integrity of data.(CVE-2020-14393)");

  script_tag(name:"affected", value:"'perl-DBI' package(s) on Huawei EulerOS Virtualization release 2.9.1.");

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

if(release == "EULEROSVIRT-2.9.1") {

  if(!isnull(res = isrpmvuln(pkg:"perl-DBI", rpm:"perl-DBI~1.642~2.h4.eulerosv2r9", rls:"EULEROSVIRT-2.9.1"))) {
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
