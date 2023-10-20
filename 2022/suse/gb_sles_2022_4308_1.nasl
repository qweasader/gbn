# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.4308.1");
  script_cve_id("CVE-2022-2211");
  script_tag(name:"creation_date", value:"2022-12-02 04:19:14 +0000 (Fri, 02 Dec 2022)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-20 09:22:00 +0000 (Wed, 20 Jul 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:4308-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:4308-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20224308-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'virt-v2v' package(s) announced via the SUSE-SU-2022:4308-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for virt-v2v fixes the following issues:

CVE-2022-2211: Fixed buffer overflow in get_keys (bsc#1201064).");

  script_tag(name:"affected", value:"'virt-v2v' package(s) on SUSE Linux Enterprise Module for Server Applications 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"virt-v2v", rpm:"virt-v2v~1.44.2~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virt-v2v-bash-completion", rpm:"virt-v2v-bash-completion~1.44.2~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virt-v2v-debuginfo", rpm:"virt-v2v-debuginfo~1.44.2~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virt-v2v-debugsource", rpm:"virt-v2v-debugsource~1.44.2~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virt-v2v-man-pages-ja", rpm:"virt-v2v-man-pages-ja~1.44.2~150400.3.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virt-v2v-man-pages-uk", rpm:"virt-v2v-man-pages-uk~1.44.2~150400.3.3.1", rls:"SLES15.0SP4"))) {
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
