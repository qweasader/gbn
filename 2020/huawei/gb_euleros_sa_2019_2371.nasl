# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2371");
  script_cve_id("CVE-2018-1000135");
  script_tag(name:"creation_date", value:"2020-01-23 12:51:43 +0000 (Thu, 23 Jan 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-03 12:29:00 +0000 (Mon, 03 Jun 2019)");

  script_name("Huawei EulerOS: Security Advisory for NetworkManager (EulerOS-SA-2019-2371)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2371");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2371");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/ubuntu/+bug/1754671");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'NetworkManager' package(s) announced via the EulerOS-SA-2019-2371 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GNOME NetworkManager version 1.10.2 and earlier contains a Information Exposure (CWE-200) vulnerability in DNS resolver that can result in Private DNS queries leaked to local network's DNS servers, while on VPN. This vulnerability appears to have been fixed in Some Ubuntu 16.04 packages were fixed, but later updates removed the fix. cf. [link moved to references] an upstream fix does not appear to be available at this time.(CVE-2018-1000135)");

  script_tag(name:"affected", value:"'NetworkManager' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager", rpm:"NetworkManager~1.10.2~16.h8", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-adsl", rpm:"NetworkManager-adsl~1.10.2~16.h8", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-bluetooth", rpm:"NetworkManager-bluetooth~1.10.2~16.h8", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-config-server", rpm:"NetworkManager-config-server~1.10.2~16.h8", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-glib", rpm:"NetworkManager-glib~1.10.2~16.h8", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-libnm", rpm:"NetworkManager-libnm~1.10.2~16.h8", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-team", rpm:"NetworkManager-team~1.10.2~16.h8", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-tui", rpm:"NetworkManager-tui~1.10.2~16.h8", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-wifi", rpm:"NetworkManager-wifi~1.10.2~16.h8", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-wwan", rpm:"NetworkManager-wwan~1.10.2~16.h8", rls:"EULEROS-2.0SP2"))) {
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
