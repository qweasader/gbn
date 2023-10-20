# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1647.1");
  script_cve_id("CVE-2022-20770", "CVE-2022-20771", "CVE-2022-20785", "CVE-2022-20792", "CVE-2022-20796");
  script_tag(name:"creation_date", value:"2022-05-13 04:52:19 +0000 (Fri, 13 May 2022)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-12 17:58:00 +0000 (Fri, 12 Aug 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1647-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1647-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221647-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav' package(s) announced via the SUSE-SU-2022:1647-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for clamav fixes the following issues:

CVE-2022-20770: Fixed a possible infinite loop vulnerability in the CHM
 file parser (bsc#1199242).

CVE-2022-20796: Fixed a possible NULL-pointer dereference crash in the
 scan verdict cache check (bsc#1199246).

CVE-2022-20771: Fixed a possible infinite loop vulnerability in the TIFF
 file parser (bsc#1199244).

CVE-2022-20785: Fixed a possible memory leak in the HTML file parser /
 Javascript normalizer (bsc#1199245).

CVE-2022-20792: Fixed a possible multi-byte heap buffer overflow write
 vulnerability in the signature database load module (bsc#1199274).");

  script_tag(name:"affected", value:"'clamav' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.103.6~3.18.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-debuginfo", rpm:"clamav-debuginfo~0.103.6~3.18.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-debugsource", rpm:"clamav-debugsource~0.103.6~3.18.1", rls:"SLES12.0SP5"))) {
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
