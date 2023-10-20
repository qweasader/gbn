# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1751.1");
  script_cve_id("CVE-2021-0071", "CVE-2021-26312", "CVE-2021-26339", "CVE-2021-26342", "CVE-2021-26347", "CVE-2021-26348", "CVE-2021-26349", "CVE-2021-26350", "CVE-2021-26364", "CVE-2021-26372", "CVE-2021-26373", "CVE-2021-26375", "CVE-2021-26376", "CVE-2021-26378", "CVE-2021-26388", "CVE-2021-33139", "CVE-2021-33155", "CVE-2021-46744");
  script_tag(name:"creation_date", value:"2022-05-20 04:30:33 +0000 (Fri, 20 May 2022)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-21 14:50:00 +0000 (Sun, 21 Nov 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1751-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1751-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221751-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-firmware' package(s) announced via the SUSE-SU-2022:1751-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kernel-firmware fixes the following issues:

Update AMD ucode and SEV firmware

CVE-2021-26339, CVE-2021-26373, CVE-2021-26347, CVE-2021-26376,
 CVE-2021-26375, CVE-2021-26378, CVE-2021-26372, CVE-2021-26339,
 CVE-2021-26348, CVE-2021-26342, CVE-2021-26388, CVE-2021-26349,
 CVE-2021-26364, CVE-2021-26312, CVE-2021-26350, CVE-2021-46744,
 bsc#1199459, bsc#1199470)

Update Intel Bluetooth firmware (INTEL-SA-00604, bsc#1195786):

CVE-2021-33139, CVE-2021-33155: Improper conditions check in the
 firmware for some Intel Wireless Bluetooth and Killer Bluetooth products
 may allow an authenticated user to potentially cause denial of service
 via adjacent access.");

  script_tag(name:"affected", value:"'kernel-firmware' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Enterprise Storage 7, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Linux Enterprise Server for SAP 15-SP2, SUSE Manager Proxy 4.1, SUSE Manager Retail Branch Server 4.1, SUSE Manager Server 4.1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~20200107~150100.3.31.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-amd", rpm:"ucode-amd~20200107~150100.3.31.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~20200107~150100.3.31.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ucode-amd", rpm:"ucode-amd~20200107~150100.3.31.1", rls:"SLES15.0SP2"))) {
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
