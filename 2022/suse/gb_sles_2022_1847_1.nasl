# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1847.1");
  script_cve_id("CVE-2021-26312", "CVE-2021-26339", "CVE-2021-26342", "CVE-2021-26347", "CVE-2021-26348", "CVE-2021-26349", "CVE-2021-26350", "CVE-2021-26364", "CVE-2021-26372", "CVE-2021-26373", "CVE-2021-26375", "CVE-2021-26376", "CVE-2021-26378", "CVE-2021-26388", "CVE-2021-46744");
  script_tag(name:"creation_date", value:"2022-05-26 04:26:34 +0000 (Thu, 26 May 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-01 16:56:20 +0000 (Wed, 01 Jun 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1847-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1847-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221847-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-firmware' package(s) announced via the SUSE-SU-2022:1847-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kernel-firmware fixes the following issues:

Update AMD ucode and SEV firmware

(CVE-2021-26339, CVE-2021-26373, CVE-2021-26347, CVE-2021-26376,
 CVE-2021-26375, CVE-2021-26378, CVE-2021-26372, CVE-2021-26339,
 CVE-2021-26348, CVE-2021-26342, CVE-2021-26388, CVE-2021-26349,
 CVE-2021-26364, CVE-2021-26312, CVE-2021-26350, CVE-2021-46744,
 bsc#1199459, bsc#1199470)");

  script_tag(name:"affected", value:"'kernel-firmware' package(s) on SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~20191118~150000.3.42.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-amd", rpm:"ucode-amd~20191118~150000.3.42.1", rls:"SLES15.0"))) {
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
