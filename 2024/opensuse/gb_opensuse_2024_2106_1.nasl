# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856261");
  script_version("2024-07-10T14:21:44+0000");
  script_cve_id("CVE-2024-35241", "CVE-2024-35242");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-07-10 14:21:44 +0000 (Wed, 10 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-06-29 04:03:13 +0000 (Sat, 29 Jun 2024)");
  script_name("openSUSE: Security Advisory for php (SUSE-SU-2024:2106-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2106-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6AXHSMH72KJXEAKMVKSVPYPHA2WHLTFK");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php'
  package(s) announced via the SUSE-SU-2024:2106-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for php-composer2 fixes the following issues:

  * CVE-2024-35241: Fixed code execution when installing packages in repository
      with specially crafted branch names (bsc#1226181).

  * CVE-2024-35242: Fixed command injection via specially crafted branch names
      during repository cloning (bsc#1226182).

  ##");

  script_tag(name:"affected", value:"'php' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"php-composer2", rpm:"php-composer2~2.2.3~150400.3.12.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-composer2", rpm:"php-composer2~2.2.3~150400.3.12.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"php-composer2", rpm:"php-composer2~2.2.3~150400.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-composer2", rpm:"php-composer2~2.2.3~150400.3.12.1", rls:"openSUSELeap15.5"))) {
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