# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0532.1");
  script_cve_id("CVE-2017-3144");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2024-02-02T14:37:49+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:49 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-07 19:09:00 +0000 (Thu, 07 Feb 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0532-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0532-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180532-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dhcp' package(s) announced via the SUSE-SU-2018:0532-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dhcp fixes several issues.
This security issue was fixed:
- CVE-2017-3144: OMAPI code didn't free socket descriptors when empty
 message is received allowing DoS (bsc#1076119).
These non-security issues were fixed:
- Optimized if and when DNS client context and ports are initted
 (bsc#1073935)
- Relax permission of dhclient-script for libguestfs (bsc#987170)
- Modify dhclient-script to handle static route updates (bsc#1023415).
- Use only the 12 least significant bits of an inbound packet's TCI value
 as the VLAN ID to fix some packages being wrongly discarded by the Linux
 packet filter. (bsc#1059061)");

  script_tag(name:"affected", value:"'dhcp' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP3.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"dhcp", rpm:"dhcp~4.3.3~10.11.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-client", rpm:"dhcp-client~4.3.3~10.11.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-client-debuginfo", rpm:"dhcp-client-debuginfo~4.3.3~10.11.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-debuginfo", rpm:"dhcp-debuginfo~4.3.3~10.11.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-debugsource", rpm:"dhcp-debugsource~4.3.3~10.11.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-relay", rpm:"dhcp-relay~4.3.3~10.11.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-relay-debuginfo", rpm:"dhcp-relay-debuginfo~4.3.3~10.11.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-server", rpm:"dhcp-server~4.3.3~10.11.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-server-debuginfo", rpm:"dhcp-server-debuginfo~4.3.3~10.11.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"dhcp", rpm:"dhcp~4.3.3~10.11.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-client", rpm:"dhcp-client~4.3.3~10.11.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-client-debuginfo", rpm:"dhcp-client-debuginfo~4.3.3~10.11.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-debuginfo", rpm:"dhcp-debuginfo~4.3.3~10.11.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-debugsource", rpm:"dhcp-debugsource~4.3.3~10.11.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-relay", rpm:"dhcp-relay~4.3.3~10.11.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-relay-debuginfo", rpm:"dhcp-relay-debuginfo~4.3.3~10.11.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-server", rpm:"dhcp-server~4.3.3~10.11.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dhcp-server-debuginfo", rpm:"dhcp-server-debuginfo~4.3.3~10.11.1", rls:"SLES12.0SP3"))) {
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
