# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856425");
  script_version("2024-09-12T07:59:53+0000");
  script_cve_id("CVE-2023-42667", "CVE-2023-49141", "CVE-2024-24853", "CVE-2024-24980", "CVE-2024-25939");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-09-12 07:59:53 +0000 (Thu, 12 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-09-06 04:00:54 +0000 (Fri, 06 Sep 2024)");
  script_name("openSUSE: Security Advisory for ucode (SUSE-SU-2024:3095-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.6|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3095-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/BDBZ43EZR5KSSC22JI7OFKRLPI6Z5IX4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ucode'
  package(s) announced via the SUSE-SU-2024:3095-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ucode-intel fixes the following issues:

  * Intel CPU Microcode was updated to the 20240813 release (bsc#1229129)

  * CVE-2024-24853: Security updates for INTEL-SA-01083

  * CVE-2024-25939: Security updates for INTEL-SA-01118

  * CVE-2024-24980: Security updates for INTEL-SA-01100

  * CVE-2023-42667: Security updates for INTEL-SA-01038

  * CVE-2023-49141: Security updates for INTEL-SA-01046 Other issues fixed:

  * Update for functional issues. Refer to Intel Core Ultra Processor for
      details.

  * Update for functional issues. Refer to 3rd Generation Intel Xeon Processor
      Scalable Family Specification Update for details.

  * Update for functional issues. Refer to 3rd Generation Intel Xeon Scalable
      Processors Specification Update for details.

  * Update for functional issues. Refer to 2nd Generation Intel Xeon Processor
      Scalable Family Specification Update for details

  * Update for functional issues. Refer to Intel Xeon D-2700 Processor
      Specification Update for details.

  * Update for functional issues. Refer to Intel Xeon E-2300 Processor
      Specification Update  for details.

  * Update for functional issues. Refer to 13th Generation Intel Core Processor
      Specification Update for details.

  * Update for functional issues. Refer to 12th Generation Intel Core Processor
      Family for details.

  * Update for functional issues. Refer to 11th Gen Intel Core Processor
      Specification Update for details.

  * Update for functional issues. Refer to 10th Gen Intel Core Processor
      Families Specification Update for details.

  * Update for functional issues. Refer to 10th Generation Intel Core Processor
      Specification Update for details.

  * Update for functional issues. Refer to 8th and 9th Generation Intel Core
      Processor Family Spec Update for details.

  * Update for functional issues. Refer to 8th Generation Intel Core Processor
      Families Specification Update for details.

  * Update for functional issues. Refer to 7th and 8th Generation Intel Core
      Processor Specification Update for details.

  * Update for functional issues. Refer to Intel Processors and Intel Core i3
      N-Series for details.

  * Update for functional issues. Refer to Intel Atom x6000E Series, and Intel
      Pentium and Celeron N and J Series Processors for Internet of Things (IoT)
      Applications for details. Updated Platforms:  Processor  Stepping
      F-M-S/PI  Old Ver  New Ver  Products
      :---------------:---------:------------:---------:---------:---------
       A ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'ucode' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel-20240813", rpm:"ucode-intel-20240813~150200.44.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"ucode-intel-20240813", rpm:"ucode-intel-20240813~150200.44.1", rls:"openSUSELeap15.5"))) {
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