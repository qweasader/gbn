# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2013.0821.1");
  script_cve_id("CVE-2013-1923");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:24 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"3.2");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:P/I:P/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2013:0821-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2013:0821-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2013/suse-su-20130821-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nfs-client' package(s) announced via the SUSE-SU-2013:0821-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes a DNS spoofing problem with NFS rpc-gssd. (CVE-2013-1923)(bnc#813464) It also adds MOUNTD_OPTIONS and GSSD_OPTIONS to /etc/sysconfig/nfs.
(bnc#818094, bnc#816897)

Security Issues:

 * CVE-2013-1923
>");

  script_tag(name:"affected", value:"'nfs-client' package(s) on SUSE Linux Enterprise Desktop 11-SP2, SUSE Linux Enterprise Server 11-SP2.");

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

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"nfs-client", rpm:"nfs-client~1.2.3~18.31.1", rls:"SLES11.0SP2"))) {
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
