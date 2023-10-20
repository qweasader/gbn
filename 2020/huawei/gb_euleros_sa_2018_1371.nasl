# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2018.1371");
  script_cve_id("CVE-2016-7795", "CVE-2017-18078");
  script_tag(name:"creation_date", value:"2020-01-23 11:23:40 +0000 (Thu, 23 Jan 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-31 18:24:00 +0000 (Mon, 31 Jan 2022)");

  script_name("Huawei EulerOS: Security Advisory for systemd (EulerOS-SA-2018-1371)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.5\.2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2018-1371");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1371");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'systemd' package(s) announced via the EulerOS-SA-2018-1371 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the way systemd handled empty notification messages. A local attacker could use this flaw to make systemd freeze its execution, preventing further management of system services, system shutdown, or zombie process collection via systemd.(CVE-2016-7795)

systemd-tmpfiles in systemd before 237 attempts to support ownership/permission changes on hardlinked files even if the fs.protected_hardlinks sysctl is turned off, which allows local users to bypass intended access restrictions via vectors involving a hard link to a file for which the user lacks write access, as demonstrated by changing the ownership of the /etc/passwd file.(CVE-2017-18078)");

  script_tag(name:"affected", value:"'systemd' package(s) on Huawei EulerOS Virtualization 2.5.2.");

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

if(release == "EULEROSVIRT-2.5.2") {

  if(!isnull(res = isrpmvuln(pkg:"libgudev1", rpm:"libgudev1~219~57.h58", rls:"EULEROSVIRT-2.5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd", rpm:"systemd~219~57.h58", rls:"EULEROSVIRT-2.5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-devel", rpm:"systemd-devel~219~57.h58", rls:"EULEROSVIRT-2.5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-libs", rpm:"systemd-libs~219~57.h58", rls:"EULEROSVIRT-2.5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-networkd", rpm:"systemd-networkd~219~57.h58", rls:"EULEROSVIRT-2.5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-python", rpm:"systemd-python~219~57.h58", rls:"EULEROSVIRT-2.5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-resolved", rpm:"systemd-resolved~219~57.h58", rls:"EULEROSVIRT-2.5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-sysv", rpm:"systemd-sysv~219~57.h58", rls:"EULEROSVIRT-2.5.2"))) {
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
