# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833338");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2023-22792", "CVE-2023-22795");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-17 19:18:14 +0000 (Fri, 17 Feb 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:17:07 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for rubygem (SUSE-SU-2023:0444-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0444-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/TOKA43MGECKIJQU7RLWHJNTZ7EGWBP55");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rubygem'
  package(s) announced via the SUSE-SU-2023:0444-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rubygem-actionpack-5_1 fixes the following issues:

  - CVE-2023-22795: Fixed ReDoS in Action Dispatch cache (bsc#1207451).

  - CVE-2023-22792: Fixed ReDoS in Action Dispatch cookies (bnc#1207455).");

  script_tag(name:"affected", value:"'rubygem' package(s) on openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-actionpack-5_1", rpm:"ruby2.5-rubygem-actionpack-5_1~5.1.4~150000.3.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-actionpack-doc-5_1", rpm:"ruby2.5-rubygem-actionpack-doc-5_1~5.1.4~150000.3.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-actionpack-5_1", rpm:"ruby2.5-rubygem-actionpack-5_1~5.1.4~150000.3.15.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-rubygem-actionpack-doc-5_1", rpm:"ruby2.5-rubygem-actionpack-doc-5_1~5.1.4~150000.3.15.1", rls:"openSUSELeap15.4"))) {
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