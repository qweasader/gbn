# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2020.1216");
  script_cve_id("CVE-2018-15686", "CVE-2018-16866", "CVE-2018-16888");
  script_tag(name:"creation_date", value:"2020-03-13 07:15:20 +0000 (Fri, 13 Mar 2020)");
  script_version("2024-02-05T14:36:56+0000");
  script_tag(name:"last_modification", value:"2024-02-05 14:36:56 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-28 16:33:47 +0000 (Wed, 28 Jul 2021)");

  script_name("Huawei EulerOS: Security Advisory for systemd (EulerOS-SA-2020-1216)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.2\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2020-1216");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2020-1216");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'systemd' package(s) announced via the EulerOS-SA-2020-1216 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered systemd does not correctly check the content of PIDFile files before using it to kill processes. When a service is run from an unprivileged user (e.g. User field set in the service file), a local attacker who is able to write to the PIDFile of the mentioned service may use this flaw to trick systemd into killing other services and/or privileged processes. Versions before v237 are vulnerable.(CVE-2018-16888)

An out of bounds read was discovered in systemd-journald in the way it parses log messages that terminate with a colon ':'. A local attacker can use this flaw to disclose process memory data. Versions from v221 to v239 are vulnerable.(CVE-2018-16866)

It was discovered that systemd is vulnerable to a state injection attack when deserializing the state of a service. Properties longer than LINE_MAX are not correctly parsed and an attacker may abuse this flaw in particularly configured services to inject, change, or corrupt the service state.(CVE-2018-15686)");

  script_tag(name:"affected", value:"'systemd' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.2.0.");

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

if(release == "EULEROSVIRTARM64-3.0.2.0") {

  if(!isnull(res = isrpmvuln(pkg:"libgudev1", rpm:"libgudev1~219~62.5.h110", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd", rpm:"systemd~219~62.5.h110", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-libs", rpm:"systemd-libs~219~62.5.h110", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-networkd", rpm:"systemd-networkd~219~62.5.h110", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-python", rpm:"systemd-python~219~62.5.h110", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-resolved", rpm:"systemd-resolved~219~62.5.h110", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-sysv", rpm:"systemd-sysv~219~62.5.h110", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-udev-compat", rpm:"systemd-udev-compat~219~62.5.h110", rls:"EULEROSVIRTARM64-3.0.2.0"))) {
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
