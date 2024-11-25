# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856559");
  script_version("2024-10-16T05:05:34+0000");
  script_cve_id("CVE-2024-4293", "CVE-2024-42934");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-10-16 05:05:34 +0000 (Wed, 16 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-10-12 04:00:24 +0000 (Sat, 12 Oct 2024)");
  script_name("openSUSE: Security Advisory for OpenIPMI (SUSE-SU-2024:3604-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3604-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/CP7HIPOEQZELJ6RZ3BNTVRPGLAJO4LTC");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'OpenIPMI'
  package(s) announced via the SUSE-SU-2024:3604-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for OpenIPMI fixes the following issues:

  * CVE-2024-42934: Fixed missing check on the authorization type on incoming
      LAN messages in IPMI simulator (bsc#1229910)");

  script_tag(name:"affected", value:"'OpenIPMI' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"libOpenIPMI0-debuginfo", rpm:"libOpenIPMI0-debuginfo~2.0.31~150400.3.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"OpenIPMI-devel", rpm:"OpenIPMI-devel~2.0.31~150400.3.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"OpenIPMI-debuginfo", rpm:"OpenIPMI-debuginfo~2.0.31~150400.3.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOpenIPMI0", rpm:"libOpenIPMI0~2.0.31~150400.3.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"OpenIPMI-python3-debuginfo", rpm:"OpenIPMI-python3-debuginfo~2.0.31~150400.3.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"OpenIPMI", rpm:"OpenIPMI~2.0.31~150400.3.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"OpenIPMI-python3", rpm:"OpenIPMI-python3~2.0.31~150400.3.5.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"OpenIPMI-debugsource", rpm:"OpenIPMI-debugsource~2.0.31~150400.3.5.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libOpenIPMI0-debuginfo", rpm:"libOpenIPMI0-debuginfo~2.0.31~150400.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"OpenIPMI-devel", rpm:"OpenIPMI-devel~2.0.31~150400.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"OpenIPMI-debuginfo", rpm:"OpenIPMI-debuginfo~2.0.31~150400.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOpenIPMI0", rpm:"libOpenIPMI0~2.0.31~150400.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"OpenIPMI-python3-debuginfo", rpm:"OpenIPMI-python3-debuginfo~2.0.31~150400.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"OpenIPMI", rpm:"OpenIPMI~2.0.31~150400.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"OpenIPMI-python3", rpm:"OpenIPMI-python3~2.0.31~150400.3.5.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"OpenIPMI-debugsource", rpm:"OpenIPMI-debugsource~2.0.31~150400.3.5.1", rls:"openSUSELeap15.5"))) {
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