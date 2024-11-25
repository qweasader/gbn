# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856225");
  script_version("2024-06-21T05:05:42+0000");
  script_cve_id("CVE-2023-50711");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-21 05:05:42 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-08 19:36:27 +0000 (Mon, 08 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-06-15 04:00:44 +0000 (Sat, 15 Jun 2024)");
  script_name("openSUSE: Security Advisory for aws (SUSE-SU-2024:1984-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1984-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/B2NCV2RPLECHO22SLWZU4SPYMILHAH3M");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'aws'
  package(s) announced via the SUSE-SU-2024:1984-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for aws-nitro-enclaves-cli fixes the following issues:

  * CVE-2023-50711: Fixed out of bounds memory accesses in embedded vmm-sys-util
      (bsc#1218501).

  ##");

  script_tag(name:"affected", value:"'aws' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"aws-nitro-enclaves-cli", rpm:"aws-nitro-enclaves-cli~1.3.0~git1.db34c02~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aws-nitro-enclaves-cli-debugsource", rpm:"aws-nitro-enclaves-cli-debugsource~1.3.0~git1.db34c02~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aws-nitro-enclaves-binaryblobs-upstream-debuginfo", rpm:"aws-nitro-enclaves-binaryblobs-upstream-debuginfo~1.3.0~git1.db34c02~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aws-nitro-enclaves-cli-debuginfo", rpm:"aws-nitro-enclaves-cli-debuginfo~1.3.0~git1.db34c02~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"system-group-ne", rpm:"system-group-ne~1.3.0~git1.db34c02~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aws-nitro-enclaves-binaryblobs-upstream", rpm:"aws-nitro-enclaves-binaryblobs-upstream~1.3.0~git1.db34c02~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aws-nitro-enclaves-cli", rpm:"aws-nitro-enclaves-cli~1.3.0~git1.db34c02~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aws-nitro-enclaves-cli-debugsource", rpm:"aws-nitro-enclaves-cli-debugsource~1.3.0~git1.db34c02~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aws-nitro-enclaves-binaryblobs-upstream-debuginfo", rpm:"aws-nitro-enclaves-binaryblobs-upstream-debuginfo~1.3.0~git1.db34c02~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aws-nitro-enclaves-cli-debuginfo", rpm:"aws-nitro-enclaves-cli-debuginfo~1.3.0~git1.db34c02~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"system-group-ne", rpm:"system-group-ne~1.3.0~git1.db34c02~150400.3.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aws-nitro-enclaves-binaryblobs-upstream", rpm:"aws-nitro-enclaves-binaryblobs-upstream~1.3.0~git1.db34c02~150400.3.6.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"aws-nitro-enclaves-cli", rpm:"aws-nitro-enclaves-cli~1.3.0~git1.db34c02~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aws-nitro-enclaves-cli-debugsource", rpm:"aws-nitro-enclaves-cli-debugsource~1.3.0~git1.db34c02~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aws-nitro-enclaves-binaryblobs-upstream-debuginfo", rpm:"aws-nitro-enclaves-binaryblobs-upstream-debuginfo~1.3.0~git1.db34c02~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aws-nitro-enclaves-cli-debuginfo", rpm:"aws-nitro-enclaves-cli-debuginfo~1.3.0~git1.db34c02~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"system-group-ne", rpm:"system-group-ne~1.3.0~git1.db34c02~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aws-nitro-enclaves-binaryblobs-upstream", rpm:"aws-nitro-enclaves-binaryblobs-upstream~1.3.0~git1.db34c02~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aws-nitro-enclaves-cli", rpm:"aws-nitro-enclaves-cli~1.3.0~git1.db34c02~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aws-nitro-enclaves-cli-debugsource", rpm:"aws-nitro-enclaves-cli-debugsource~1.3.0~git1.db34c02~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aws-nitro-enclaves-binaryblobs-upstream-debuginfo", rpm:"aws-nitro-enclaves-binaryblobs-upstream-debuginfo~1.3.0~git1.db34c02~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aws-nitro-enclaves-cli-debuginfo", rpm:"aws-nitro-enclaves-cli-debuginfo~1.3.0~git1.db34c02~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"system-group-ne", rpm:"system-group-ne~1.3.0~git1.db34c02~150400.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aws-nitro-enclaves-binaryblobs-upstream", rpm:"aws-nitro-enclaves-binaryblobs-upstream~1.3.0~git1.db34c02~150400.3.6.1", rls:"openSUSELeap15.5"))) {
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