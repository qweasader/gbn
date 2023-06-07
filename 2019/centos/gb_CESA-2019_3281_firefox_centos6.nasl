# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.883129");
  script_version("2023-05-10T09:37:12+0000");
  script_cve_id("CVE-2019-11757", "CVE-2019-11758", "CVE-2019-11759", "CVE-2019-11760", "CVE-2019-11761", "CVE-2019-11762", "CVE-2019-11763", "CVE-2019-11764");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-05-10 09:37:12 +0000 (Wed, 10 May 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-14 19:15:00 +0000 (Sat, 14 Mar 2020)");
  script_tag(name:"creation_date", value:"2019-11-02 03:00:46 +0000 (Sat, 02 Nov 2019)");
  script_name("CentOS Update for firefox CESA-2019:3281 centos6");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");

  script_xref(name:"CESA", value:"2019:3281");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-November/023501.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the CESA-2019:3281 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Firefox is an open-source web browser, designed for standards
compliance, performance, and portability.

This update upgrades Firefox to version 68.2.0 ESR.

Security Fix(es):

  * Mozilla: Memory safety bugs fixed in Firefox 70 and Firefox ESR 68.2
(CVE-2019-11764)

  * Mozilla: Use-after-free when creating index updates in IndexedDB
(CVE-2019-11757)

  * Mozilla: Potentially exploitable crash due to 360 Total Security
(CVE-2019-11758)

  * Mozilla: Stack buffer overflow in HKDF output (CVE-2019-11759)

  * Mozilla: Stack buffer overflow in WebRTC networking (CVE-2019-11760)

  * Mozilla: Unintended access to a privileged JSONView object
(CVE-2019-11761)

  * Mozilla: document.domain-based origin isolation has same-origin-property
violation (CVE-2019-11762)

  * Mozilla: Incorrect HTML parsing results in XSS bypass technique
(CVE-2019-11763)

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

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~68.2.0~4.el6.centos", rls:"CentOS6"))) {
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