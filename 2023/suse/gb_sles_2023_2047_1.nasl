# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2047.1");
  script_tag(name:"creation_date", value:"2023-04-27 04:18:08 +0000 (Thu, 27 Apr 2023)");
  script_version("2023-06-20T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:26 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2047-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2047-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232047-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl-ibmca' package(s) announced via the SUSE-SU-2023:2047-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssl-ibmca fixes the following issues:

Fixed a timing-based side channel attack in RSA in the IBMCA engine (openssl-ibmca)");

  script_tag(name:"affected", value:"'openssl-ibmca' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"openssl-ibmca", rpm:"openssl-ibmca~2.0.3~4.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-ibmca-32bit", rpm:"openssl-ibmca-32bit~2.0.3~4.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-ibmca-debuginfo", rpm:"openssl-ibmca-debuginfo~2.0.3~4.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-ibmca-debuginfo-32bit", rpm:"openssl-ibmca-debuginfo-32bit~2.0.3~4.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-ibmca-debugsource", rpm:"openssl-ibmca-debugsource~2.0.3~4.3.1", rls:"SLES12.0SP5"))) {
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
