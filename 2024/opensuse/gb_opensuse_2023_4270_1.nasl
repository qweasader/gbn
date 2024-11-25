# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833022");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2019-9545", "CVE-2022-37052");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-04 15:10:56 +0000 (Mon, 04 Mar 2019)");
  script_tag(name:"creation_date", value:"2024-03-04 08:06:36 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for poppler (SUSE-SU-2023:4270-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4270-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KEMZHWHSG2L5EFBVSGDZMSBWMDZXVGUX");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler'
  package(s) announced via the SUSE-SU-2023:4270-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for poppler fixes the following issues:

  * CVE-2019-9545: Fixed an uncontrolled recursion issue that could cause a
      crash (bsc#1128114).

  * CVE-2022-37052: Fixed a crash that could be triggered when opening a crafted
      file (bsc#1214726).

  ##");

  script_tag(name:"affected", value:"'poppler' package(s) on openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpoppler73", rpm:"libpoppler73~0.62.0~150000.4.31.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler73-debuginfo", rpm:"libpoppler73-debuginfo~0.62.0~150000.4.31.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler73-32bit-debuginfo", rpm:"libpoppler73-32bit-debuginfo~0.62.0~150000.4.31.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler73-32bit", rpm:"libpoppler73-32bit~0.62.0~150000.4.31.1##", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler73", rpm:"libpoppler73~0.62.0~150000.4.31.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler73-debuginfo", rpm:"libpoppler73-debuginfo~0.62.0~150000.4.31.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler73-32bit-debuginfo", rpm:"libpoppler73-32bit-debuginfo~0.62.0~150000.4.31.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler73-32bit", rpm:"libpoppler73-32bit~0.62.0~150000.4.31.1##", rls:"openSUSELeap15.4"))) {
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