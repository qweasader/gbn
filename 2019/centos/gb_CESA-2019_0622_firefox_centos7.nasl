# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.883026");
  script_version("2023-05-10T09:37:12+0000");
  script_cve_id("CVE-2018-18506", "CVE-2019-9788", "CVE-2019-9790", "CVE-2019-9791", "CVE-2019-9792", "CVE-2019-9793", "CVE-2019-9795", "CVE-2019-9796");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-05-10 09:37:12 +0000 (Wed, 10 May 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-30 18:47:00 +0000 (Wed, 30 Mar 2022)");
  script_tag(name:"creation_date", value:"2019-03-28 13:45:07 +0000 (Thu, 28 Mar 2019)");
  script_name("CentOS Update for firefox CESA-2019:0622 centos7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"CESA", value:"2019:0622");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-March/023250.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the CESA-2019:0622 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Firefox is an open-source web browser, designed for standards
compliance, performance, and portability.

This update upgrades Firefox to version 60.6.0 ESR.

Security Fix(es):

  * Mozilla: Memory safety bugs fixed in Firefox 66 and Firefox ESR 60.6
(CVE-2019-9788)

  * Mozilla: Use-after-free when removing in-use DOM elements (CVE-2019-9790)

  * Mozilla: Type inference is incorrect for constructors entered through
on-stack replacement with IonMonkey (CVE-2019-9791)

  * Mozilla: IonMonkey leaks JS_OPTIMIZED_OUT magic value to script
(CVE-2019-9792)

  * Mozilla: Improper bounds checks when Spectre mitigations are disabled
(CVE-2019-9793)

  * Mozilla: Type-confusion in IonMonkey JIT compiler (CVE-2019-9795)

  * Mozilla: Use-after-free with SMIL animation controller (CVE-2019-9796)

  * Mozilla: Proxy Auto-Configuration file can define localhost access to be
proxied (CVE-2018-18506)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'firefox' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~60.6.0~3.el7.centos", rls:"CentOS7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
