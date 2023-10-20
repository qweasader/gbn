# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.1178");
  script_cve_id("CVE-2020-13529");
  script_tag(name:"creation_date", value:"2022-02-24 03:23:47 +0000 (Thu, 24 Feb 2022)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"2.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 21:15:00 +0000 (Tue, 20 Jul 2021)");

  script_name("Huawei EulerOS: Security Advisory for NetworkManager (EulerOS-SA-2022-1178)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP3");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-1178");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-1178");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'NetworkManager' package(s) announced via the EulerOS-SA-2022-1178 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An exploitable denial of service vulnerability exists in systemd which does not fully implement RFC3203, as it does not support authentication of FORCERENEW packets. A specially crafted DHCP FORCERENEW packet can cause a system, running the DHCP client, to be vulnerable to a DHCP ACK spoofing attack. An attacker can forge a pair of FORCERENEW and DCHPACK packets to reconfigure the system with arbitrary network settings.(CVE-2020-13529)");

  script_tag(name:"affected", value:"'NetworkManager' package(s) on Huawei EulerOS V2.0SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager", rpm:"NetworkManager~1.10.2~16.h10", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-adsl", rpm:"NetworkManager-adsl~1.10.2~16.h10", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-bluetooth", rpm:"NetworkManager-bluetooth~1.10.2~16.h10", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-config-server", rpm:"NetworkManager-config-server~1.10.2~16.h10", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-glib", rpm:"NetworkManager-glib~1.10.2~16.h10", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-libnm", rpm:"NetworkManager-libnm~1.10.2~16.h10", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-team", rpm:"NetworkManager-team~1.10.2~16.h10", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-tui", rpm:"NetworkManager-tui~1.10.2~16.h10", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-wifi", rpm:"NetworkManager-wifi~1.10.2~16.h10", rls:"EULEROS-2.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"NetworkManager-wwan", rpm:"NetworkManager-wwan~1.10.2~16.h10", rls:"EULEROS-2.0SP3"))) {
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
