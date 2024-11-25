# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856528");
  script_version("2024-10-10T07:25:31+0000");
  script_cve_id("CVE-2024-4293", "CVE-2024-42934");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-10-04 04:00:58 +0000 (Fri, 04 Oct 2024)");
  script_name("openSUSE: Security Advisory for OpenIPMI (SUSE-SU-2024:3505-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3505-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/5KFXLIDF3XMGNOSAY6YMM5L55CSZD77Q");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'OpenIPMI'
  package(s) announced via the SUSE-SU-2024:3505-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for OpenIPMI fixes the following issues:

  * CVE-2024-42934: crash or message authentication bypass on IPMI simulator due
      to missing bounds check. (bsc#1229910)");

  script_tag(name:"affected", value:"'OpenIPMI' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"OpenIPMI-debugsource", rpm:"OpenIPMI-debugsource~2.0.31~150600.10.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"OpenIPMI-python3-debuginfo", rpm:"OpenIPMI-python3-debuginfo~2.0.31~150600.10.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"OpenIPMI-debuginfo", rpm:"OpenIPMI-debuginfo~2.0.31~150600.10.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"OpenIPMI-python3", rpm:"OpenIPMI-python3~2.0.31~150600.10.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOpenIPMI0-debuginfo", rpm:"libOpenIPMI0-debuginfo~2.0.31~150600.10.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"OpenIPMI", rpm:"OpenIPMI~2.0.31~150600.10.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"OpenIPMI-devel", rpm:"OpenIPMI-devel~2.0.31~150600.10.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libOpenIPMI0", rpm:"libOpenIPMI0~2.0.31~150600.10.3.1", rls:"openSUSELeap15.6"))) {
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