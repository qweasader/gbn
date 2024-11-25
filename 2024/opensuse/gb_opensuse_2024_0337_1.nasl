# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856610");
  script_version("2024-10-30T05:05:27+0000");
  script_cve_id("CVE-2024-9954", "CVE-2024-9955", "CVE-2024-9956", "CVE-2024-9957", "CVE-2024-9958", "CVE-2024-9959", "CVE-2024-9960", "CVE-2024-9961", "CVE-2024-9962", "CVE-2024-9963", "CVE-2024-9964", "CVE-2024-9965", "CVE-2024-9966");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-10-30 05:05:27 +0000 (Wed, 30 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-17 20:06:01 +0000 (Thu, 17 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-10-19 04:00:30 +0000 (Sat, 19 Oct 2024)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2024:0337-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0337-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/T2MFLX2ZRDN67URDWGTQ2CAJVYDFICNP");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2024:0337-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

     Chromium 130.0.6723.58 (boo#1231694)

  * CVE-2024-9954: Use after free in AI

  * CVE-2024-9955: Use after free in Web Authentication

  * CVE-2024-9956: Inappropriate implementation in Web Authentication

  * CVE-2024-9957: Use after free in UI

  * CVE-2024-9958: Inappropriate implementation in PictureInPicture

  * CVE-2024-9959: Use after free in DevTools

  * CVE-2024-9960: Use after free in Dawn

  * CVE-2024-9961: Use after free in Parcel Tracking

  * CVE-2024-9962: Inappropriate implementation in Permissions

  * CVE-2024-9963: Insufficient data validation in Downloads

  * CVE-2024-9964: Inappropriate implementation in Payments

  * CVE-2024-9965: Insufficient data validation in DevTools

  * CVE-2024-9966: Inappropriate implementation in Navigations");

  script_tag(name:"affected", value:"'chromium' package(s) on openSUSE Backports SLE-15-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~130.0.6723.58~bp155.2.129.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~130.0.6723.58~bp155.2.129.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
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