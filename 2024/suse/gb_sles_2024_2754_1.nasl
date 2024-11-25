# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.2754.1");
  script_cve_id("CVE-2024-28180", "CVE-2024-3727");
  script_tag(name:"creation_date", value:"2024-08-06 04:24:49 +0000 (Tue, 06 Aug 2024)");
  script_version("2024-08-06T05:05:45+0000");
  script_tag(name:"last_modification", value:"2024-08-06 05:05:45 +0000 (Tue, 06 Aug 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:2754-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2754-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242754-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'skopeo' package(s) announced via the SUSE-SU-2024:2754-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for skopeo fixes the following issues:
Update to version 1.14.4:

CVE-2024-3727: Fixed a vulnerability that allows attackers to trigger unexpected authenticated registry accesses on behalf of a victim user, resource exhaustion, local path traversal and other attacks. (bsc#1224123)");

  script_tag(name:"affected", value:"'skopeo' package(s) on SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP2.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libgpg-error-debugsource", rpm:"libgpg-error-debugsource~1.29~150000.3.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgpg-error-devel", rpm:"libgpg-error-devel~1.29~150000.3.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgpg-error-devel-debuginfo", rpm:"libgpg-error-devel-debuginfo~1.29~150000.3.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgpg-error0", rpm:"libgpg-error0~1.29~150000.3.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgpg-error0-32bit", rpm:"libgpg-error0-32bit~1.29~150000.3.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgpg-error0-32bit-debuginfo", rpm:"libgpg-error0-32bit-debuginfo~1.29~150000.3.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgpg-error0-debuginfo", rpm:"libgpg-error0-debuginfo~1.29~150000.3.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"skopeo", rpm:"skopeo~1.14.4~150000.4.26.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"skopeo-debuginfo", rpm:"skopeo-debuginfo~1.14.4~150000.4.26.1", rls:"SLES15.0SP2"))) {
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
