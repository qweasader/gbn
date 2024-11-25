# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856402");
  script_version("2024-11-05T05:05:33+0000");
  script_cve_id("CVE-2024-25641", "CVE-2024-27082", "CVE-2024-29894", "CVE-2024-31443", "CVE-2024-31444", "CVE-2024-31445", "CVE-2024-31458", "CVE-2024-31459", "CVE-2024-31460", "CVE-2024-34340");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-11-05 05:05:33 +0000 (Tue, 05 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-09-03 04:00:32 +0000 (Tue, 03 Sep 2024)");
  script_name("openSUSE: Security Advisory for cacti, cacti (openSUSE-SU-2024:0274-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0274-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/TICTDSNKZDF27FVLCXHQWQDX7E7X3TDN");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cacti, cacti'
  package(s) announced via the openSUSE-SU-2024:0274-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cacti, cacti-spine fixes the following issues:

  - cacti 1.2.27:

  * CVE-2024-34340: Authentication Bypass when using using older password
         hashes (boo#1224240)

  * CVE-2024-25641: RCE vulnerability when importing packages (boo#1224229)

  * CVE-2024-31459: RCE vulnerability when plugins include files
         (boo#1224238)

  * CVE-2024-31460: SQL Injection vulnerability when using tree rules
         through Automation API (boo#1224239)

  * CVE-2024-29894: XSS vulnerability when using JavaScript based
         messaging API (boo#1224231)

  * CVE-2024-31458: SQL Injection vulnerability when using form templates
         (boo#1224241)

  * CVE-2024-31444: XSS vulnerability when reading tree rules with
         Automation API (boo#1224236)

  * CVE-2024-31443: XSS vulnerability when managing data queries
         (boo#1224235)

  * CVE-2024-31445: SQL Injection vulnerability when retrieving graphs
         using Automation API (boo#1224237)

  * CVE-2024-27082: XSS vulnerability when managing trees (boo#1224230)

  * Improve PHP 8.3 support

  * When importing packages via command line, data source profile could
         not be selected

  * When changing password, returning to previous page does not always work

  * When using LDAP authentication the first time, warnings may appear in
         logs

  * When editing/viewing devices, add IPv6 info to hostname tooltip

  * Improve speed of polling when Boost is enabled

  * Improve support for Half-Hour time zones

  * When user session not found, device lists can be incorrectly returned

  * On import, legacy templates may generate warnings

  * Improve support for alternate locations of Ping

  * Improve PHP 8.1 support for Installer

  * Fix issues with number formatting

  * Improve PHP 8.1 support when SpikeKill is run first time

  * Improve PHP 8.1 support for SpikeKill

  * When using Chinese to search for graphics, garbled characters appear.

  * When importing templates, preview mode will not always load

  * When remote poller is installed, MySQL TimeZone DB checks are not
         performed

  * When Remote Poller installation completes, no finish button is shown

  * Unauthorized agents should be recorded into logs

  * Poller cache may not always update if hostname changes

  * When using CMD poller, Failure and Recovery dates may have incorrect
         values

  * Saving a Tree can cause the tree to become unpublished

  * Web Basic Authentica ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'cacti, cacti' package(s) on openSUSE Backports SLE-15-SP5.");

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

if(release == "openSUSEBackportsSLE-15-SP5") {

  if(!isnull(res = isrpmvuln(pkg:"cacti-spine", rpm:"cacti-spine~1.2.27~bp155.2.9.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cacti", rpm:"cacti~1.2.27~bp155.2.9.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
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