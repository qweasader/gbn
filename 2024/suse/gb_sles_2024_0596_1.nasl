# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0596.1");
  script_cve_id("CVE-2023-51385");
  script_tag(name:"creation_date", value:"2024-02-23 04:22:38 +0000 (Fri, 23 Feb 2024)");
  script_version("2024-02-23T05:07:12+0000");
  script_tag(name:"last_modification", value:"2024-02-23 05:07:12 +0000 (Fri, 23 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-03 19:40:07 +0000 (Wed, 03 Jan 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0596-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0596-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240596-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh' package(s) announced via the SUSE-SU-2024:0596-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssh fixes the following issues:

CVE-2023-51385: Limit the use of shell metacharacters in host- and
 user names to avoid command injection. (bsc#1218215)");

  script_tag(name:"affected", value:"'openssh' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise Desktop 15-SP4, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise High Performance Computing 15-SP4, SUSE Linux Enterprise Micro 5.1, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Micro 5.3, SUSE Linux Enterprise Micro 5.4, SUSE Linux Enterprise Micro 5.5, SUSE Linux Enterprise Micro for Rancher 5.2, SUSE Linux Enterprise Micro for Rancher 5.3, SUSE Linux Enterprise Micro for Rancher 5.4, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Manager Proxy 4.3, SUSE Manager Retail Branch Server 4.3, SUSE Manager Server 4.3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"openssh", rpm:"openssh~8.4p1~150300.3.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass-gnome", rpm:"openssh-askpass-gnome~8.4p1~150300.3.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass-gnome-debuginfo", rpm:"openssh-askpass-gnome-debuginfo~8.4p1~150300.3.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass-gnome-debugsource", rpm:"openssh-askpass-gnome-debugsource~8.4p1~150300.3.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-clients", rpm:"openssh-clients~8.4p1~150300.3.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-clients-debuginfo", rpm:"openssh-clients-debuginfo~8.4p1~150300.3.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-common", rpm:"openssh-common~8.4p1~150300.3.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-common-debuginfo", rpm:"openssh-common-debuginfo~8.4p1~150300.3.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-debuginfo", rpm:"openssh-debuginfo~8.4p1~150300.3.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-debugsource", rpm:"openssh-debugsource~8.4p1~150300.3.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-fips", rpm:"openssh-fips~8.4p1~150300.3.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-helpers", rpm:"openssh-helpers~8.4p1~150300.3.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-helpers-debuginfo", rpm:"openssh-helpers-debuginfo~8.4p1~150300.3.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-server", rpm:"openssh-server~8.4p1~150300.3.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-server-debuginfo", rpm:"openssh-server-debuginfo~8.4p1~150300.3.30.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"openssh", rpm:"openssh~8.4p1~150300.3.30.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass-gnome", rpm:"openssh-askpass-gnome~8.4p1~150300.3.30.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass-gnome-debuginfo", rpm:"openssh-askpass-gnome-debuginfo~8.4p1~150300.3.30.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass-gnome-debugsource", rpm:"openssh-askpass-gnome-debugsource~8.4p1~150300.3.30.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-clients", rpm:"openssh-clients~8.4p1~150300.3.30.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-clients-debuginfo", rpm:"openssh-clients-debuginfo~8.4p1~150300.3.30.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-common", rpm:"openssh-common~8.4p1~150300.3.30.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-common-debuginfo", rpm:"openssh-common-debuginfo~8.4p1~150300.3.30.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-debuginfo", rpm:"openssh-debuginfo~8.4p1~150300.3.30.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-debugsource", rpm:"openssh-debugsource~8.4p1~150300.3.30.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-fips", rpm:"openssh-fips~8.4p1~150300.3.30.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-helpers", rpm:"openssh-helpers~8.4p1~150300.3.30.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-helpers-debuginfo", rpm:"openssh-helpers-debuginfo~8.4p1~150300.3.30.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-server", rpm:"openssh-server~8.4p1~150300.3.30.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-server-debuginfo", rpm:"openssh-server-debuginfo~8.4p1~150300.3.30.1", rls:"SLES15.0SP4"))) {
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
