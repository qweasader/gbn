# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.883080");
  script_version("2023-05-10T09:37:12+0000");
  script_cve_id("CVE-2019-9811", "CVE-2019-11709", "CVE-2019-11711", "CVE-2019-11712", "CVE-2019-11713", "CVE-2019-11715", "CVE-2019-11717", "CVE-2019-11730");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-05-10 09:37:12 +0000 (Wed, 10 May 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-18 17:02:00 +0000 (Mon, 18 Apr 2022)");
  script_tag(name:"creation_date", value:"2019-07-13 02:00:38 +0000 (Sat, 13 Jul 2019)");
  script_name("CentOS Update for firefox CESA-2019:1765 centos6");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");

  script_xref(name:"CESA", value:"2019:1765");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-July/023364.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the CESA-2019:1765 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Firefox is an open-source web browser, designed for standards
compliance, performance, and portability.

This update upgrades Firefox to version 60.8.0 ESR.

Security Fix(es):

  * Mozilla: Memory safety bugs fixed in Firefox 68 and Firefox ESR 60.8
(CVE-2019-11709)

  * Mozilla: Sandbox escape via installation of malicious language pack
(CVE-2019-9811)

  * Mozilla: Script injection within domain through inner window reuse
(CVE-2019-11711)

  * Mozilla: Cross-origin POST requests can be made with NPAPI plugins by
following 308 redirects (CVE-2019-11712)

  * Mozilla: Use-after-free with HTTP/2 cached stream (CVE-2019-11713)

  * Mozilla: HTML parsing error can contribute to content XSS
(CVE-2019-11715)

  * Mozilla: Caret character improperly escaped in origins (CVE-2019-11717)

  * Mozilla: Same-origin policy treats all files in a directory as having the
same-origin (CVE-2019-11730)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'firefox' package(s) on CentOS 6.");

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

if(release == "CentOS6") {

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~60.8.0~1.el6.centos", rls:"CentOS6"))) {
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