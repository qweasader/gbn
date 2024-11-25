# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856100");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2024-29131", "CVE-2024-29133");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"creation_date", value:"2024-04-25 01:00:24 +0000 (Thu, 25 Apr 2024)");
  script_name("openSUSE: Security Advisory for apache (SUSE-SU-2024:1377-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1377-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/EWVLKUXIFPFAIRZWAEUTQ56ELBWYHH7J");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache'
  package(s) announced via the SUSE-SU-2024:1377-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for apache-commons-configuration fixes the following issues:

  * CVE-2024-29131: Fixed StackOverflowError adding property in
      AbstractListDelimiterHandler.flattenIterator() (bsc#1221797).

  * CVE-2024-29133: Fixed StackOverflowError calling
      ListDelimiterHandler.flatten(Object, int) with a cyclical object tree
      (bsc#1221793).

  ##");

  script_tag(name:"affected", value:"'apache' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-configuration-javadoc", rpm:"apache-commons-configuration-javadoc~1.10~150200.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-configuration", rpm:"apache-commons-configuration~1.10~150200.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-configuration-javadoc", rpm:"apache-commons-configuration-javadoc~1.10~150200.3.11.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache-commons-configuration", rpm:"apache-commons-configuration~1.10~150200.3.11.1", rls:"openSUSELeap15.5"))) {
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