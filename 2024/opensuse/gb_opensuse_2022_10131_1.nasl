# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833374");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2022-3196", "CVE-2022-3197", "CVE-2022-3198", "CVE-2022-3199", "CVE-2022-3200", "CVE-2022-3201");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-28 18:16:21 +0000 (Wed, 28 Sep 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:23:08 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for opera (openSUSE-SU-2022:10131-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4:NonFree");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:10131-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/G6TT4MGVDNPD2HCAIKGPG7EJ4Z5DSRJL");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opera'
  package(s) announced via the openSUSE-SU-2022:10131-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opera fixes the following issues:
  Update to 91.0.4516.20

  - CHR-9019 Update chromium on desktop-stable-105-4516 to 105.0.5195.127

  - DNA-101312 Allow changing logged in user with BrowserAPI

  - The update to chromium 105.0.5195.127 fixes following issues:
       CVE-2022-3196, CVE-2022-3197, CVE-2022-3198, CVE-2022-3199,
       CVE-2022-3200, CVE-2022-3201
  Update to 91.0.4516.16

  - CHR-9010 Update chromium on desktop-stable-105-4516 to 105.0.5195.102

  - DNA-101447 Incorrect translation in Russian

  - DNA-101482 Crash at ProfileKey::GetProtoDatabaseProvider()

  - DNA-101495 Performance Stint 2022

  - DNA-101551 Add version number info to browser API

  - DNA-101662 Suppress 'Allowing special test code paths' warning on
         buildbot

  - DNA-101753 News don't show after close browser

  - DNA-101760 Translations for O91

  - DNA-101799 Crash at opera::SuggestionList::SortAndCull

  - DNA-101812 Sponsored site gets chosen as default entry when typing
         part of top-level domain

  - DNA-101876 Promote 91 to stable

  - Update to 90.0.4480.107

  - DNA-100664 Shopping corner widget

  - DNA-101495 Performance Stint 2022

  - DNA-101753 News dont show after close browser

  - DNA-101799 Crash at opera::SuggestionList::SortAndCull");

  script_tag(name:"affected", value:"'opera' package(s) on openSUSE Leap 15.4:NonFree.");

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

if(release == "openSUSELeap15.4:NonFree") {

  if(!isnull(res = isrpmvuln(pkg:"opera", rpm:"opera~91.0.4516.20~lp154.2.23.1", rls:"openSUSELeap15.4:NonFree"))) {
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
