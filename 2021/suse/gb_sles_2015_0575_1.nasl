# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0575.1");
  script_cve_id("CVE-2014-9679");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:13 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:48+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:48 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0575-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0575-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150575-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups' package(s) announced via the SUSE-SU-2015:0575-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"cups has been updated to fix one security issue:

 * CVE-2014-9679: A malformed compressed raster file can trigger a
 buffer overflow in cupsRasterReadPixels (bnc#917799).

Security Issues:

 * CVE-2014-9679");

  script_tag(name:"affected", value:"'cups' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Software Development Kit 11-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"cups", rpm:"cups~1.3.9~8.46.54.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-client", rpm:"cups-client~1.3.9~8.46.54.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.3.9~8.46.54.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-libs-32bit", rpm:"cups-libs-32bit~1.3.9~8.46.54.2", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cups-libs-x86", rpm:"cups-libs-x86~1.3.9~8.46.54.2", rls:"SLES11.0SP3"))) {
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
