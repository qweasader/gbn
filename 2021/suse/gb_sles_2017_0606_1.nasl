# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.0606.1");
  script_cve_id("CVE-2016-10009", "CVE-2016-10011", "CVE-2016-8858");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:00 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-19 20:02:00 +0000 (Wed, 19 Sep 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:0606-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:0606-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20170606-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssh' package(s) announced via the SUSE-SU-2017:0606-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssh fixes the following issues:
Security issues fixed:
- CVE-2016-8858: prevent resource depletion during key exchange
 (bsc#1005480)
- CVE-2016-10009: limit directories for loading PKCS11 modules to avoid
 privilege escalation (bsc#1016366)
- CVE-2016-10011: Prevent possible leaks of host private keys to
 low-privilege process handling authentication (bsc#1016369)
Non security issues fixed:
- Properly verify CIDR masks in the AllowUsers and DenyUsers configuration
 lists (bsc#1005893)");

  script_tag(name:"affected", value:"'openssh' package(s) on SUSE Linux Enterprise Debuginfo 11-SP3, SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Manager 2.1, SUSE Manager Proxy 2.1, SUSE OpenStack Cloud 5.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"openssh", rpm:"openssh~6.2p2~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass", rpm:"openssh-askpass~6.2p2~0.40.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssh-askpass-gnome", rpm:"openssh-askpass-gnome~6.2p2~0.40.3", rls:"SLES11.0SP3"))) {
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
