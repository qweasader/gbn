# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856511");
  script_version("2024-10-10T07:25:31+0000");
  script_cve_id("CVE-2024-43806");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-09-26 04:01:51 +0000 (Thu, 26 Sep 2024)");
  script_name("openSUSE: Security Advisory for rage (SUSE-SU-2024:3404-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.6|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3404-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/FNL22ECHJXTQLDCBPDLHN4A7M4KP5ITU");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rage'
  package(s) announced via the SUSE-SU-2024:3404-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rage-encryption fixes the following issues:

  * Update to version 0.10.0

  * CVE-2024-43806: Fixed rustix::fs::Dir iterator with the linux_raw backend
      that can cause memory exhaustion. (bsc#1229959)");

  script_tag(name:"affected", value:"'rage' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"rage-encryption", rpm:"rage-encryption~0.10.0+0~150500.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rage-encryption-bash-completion", rpm:"rage-encryption-bash-completion~0.10.0+0~150500.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rage-encryption-fish-completion", rpm:"rage-encryption-fish-completion~0.10.0+0~150500.3.6.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rage-encryption-zsh-completion", rpm:"rage-encryption-zsh-completion~0.10.0+0~150500.3.6.1", rls:"openSUSELeap15.6"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"rage-encryption", rpm:"rage-encryption~0.10.0+0~150500.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rage-encryption-bash-completion", rpm:"rage-encryption-bash-completion~0.10.0+0~150500.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rage-encryption-fish-completion", rpm:"rage-encryption-fish-completion~0.10.0+0~150500.3.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rage-encryption-zsh-completion", rpm:"rage-encryption-zsh-completion~0.10.0+0~150500.3.6.1", rls:"openSUSELeap15.5"))) {
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