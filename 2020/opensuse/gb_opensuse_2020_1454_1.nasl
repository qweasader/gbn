# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.853432");
  script_version("2024-06-26T05:05:39+0000");
  script_cve_id("CVE-2020-15953");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-22 22:15:00 +0000 (Tue, 22 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-20 03:00:47 +0000 (Sun, 20 Sep 2020)");
  script_name("openSUSE: Security Advisory for libetpan (openSUSE-SU-2020:1454-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"openSUSE-SU", value:"2020:1454-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-09/msg00060.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libetpan'
  package(s) announced via the openSUSE-SU-2020:1454-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libetpan fixes the following issues:

  Update to 1.9.4 (boo#1174579, CVE-2020-15953):

  * Bugfixes on QUOTA

  * Various warning fixes & build fixes

  Update to version 1.9.3

  * Added IMAP CLIENTID / SMTP CLIENTID support

  * Use Cyrus SASL 2.1.27

  Update to version 1.9.2

  * Support of TLS SNI

  * LMDB for cache DB

  * Fixed build with recent versions of curl


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1454=1");

  script_tag(name:"affected", value:"'libetpan' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"libetpan-debugsource", rpm:"libetpan-debugsource~1.9.4~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libetpan-devel", rpm:"libetpan-devel~1.9.4~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libetpan20", rpm:"libetpan20~1.9.4~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libetpan20-debuginfo", rpm:"libetpan20-debuginfo~1.9.4~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
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
