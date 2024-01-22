# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.883108");
  script_version("2023-10-27T16:11:32+0000");
  script_cve_id("CVE-2019-9812", "CVE-2019-11733", "CVE-2019-11740", "CVE-2019-11742", "CVE-2019-11743", "CVE-2019-11744", "CVE-2019-11746", "CVE-2019-11752");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:32 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-09-19 02:02:44 +0000 (Thu, 19 Sep 2019)");
  script_name("CentOS Update for firefox CESA-2019:2729 centos7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"CESA", value:"2019:2729");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-September/023448.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the CESA-2019:2729 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Firefox is an open-source web browser, designed for standards
compliance, performance, and portability.

This update upgrades Firefox to version 60.9.0 ESR.

Security Fix(es):

  * Mozilla: Sandbox escape through Firefox Sync (CVE-2019-9812)

  * Mozilla: Memory safety bugs fixed in Firefox 69, Firefox ESR 68.1, and
Firefox ESR 60.9 (CVE-2019-11740)

  * Mozilla: Same-origin policy violation with SVG filters and canvas to
steal cross-origin images (CVE-2019-11742)

  * Mozilla: XSS by breaking out of title and textarea elements using
innerHTML (CVE-2019-11744)

  * Mozilla: Use-after-free while manipulating video (CVE-2019-11746)

  * Mozilla: Use-after-free while extracting a key value in IndexedDB
(CVE-2019-11752)

  * firefox: stored passwords in 'Saved Logins' can be copied without master
password entry (CVE-2019-11733)

  * Mozilla: Cross-origin access to unload event attributes (CVE-2019-11743)

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

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~60.9.0~1.el7.centos", rls:"CentOS7"))) {
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
