# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856707");
  script_version("2024-11-13T05:05:39+0000");
  script_cve_id("CVE-2024-0132", "CVE-2024-0133", "CVE-2024-10005", "CVE-2024-10006", "CVE-2024-10086", "CVE-2024-10452", "CVE-2024-39720", "CVE-2024-46872", "CVE-2024-47401", "CVE-2024-50052", "CVE-2024-50354", "CVE-2024-8185");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-11-13 05:05:39 +0000 (Wed, 13 Nov 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-02 14:45:36 +0000 (Wed, 02 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-11-09 05:00:26 +0000 (Sat, 09 Nov 2024)");
  script_name("openSUSE: Security Advisory for govulncheck (SUSE-SU-2024:3950-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.6|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3950-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/A336MJDFW7GHNADXUMD5DVRU7NGPTCPH");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'govulncheck'
  package(s) announced via the SUSE-SU-2024:3950-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for govulncheck-vulndb fixes the following issues:

  * Update to version 0.0.20241104T154416 2024-11-04T15:44:16Z. Refs
      jsc#PED-11136 Go CVE Numbering Authority IDs added or updated with aliases:

  * GO-2024-3233 CVE-2024-46872 GHSA-762g-9p7f-mrww

  * GO-2024-3234 CVE-2024-47401 GHSA-762v-rq7q-ff97

  * GO-2024-3235 CVE-2024-50052 GHSA-g376-m3h3-mj4r

  * GO-2024-3237 CVE-2024-0133 GHSA-f748-7hpg-88ch

  * GO-2024-3239 CVE-2024-0132 GHSA-mjjw-553x-87pq

  * GO-2024-3240 CVE-2024-10452 GHSA-66c4-2g2v-54qw

  * GO-2024-3241 CVE-2024-10006 GHSA-5c4w-8hhh-3c3h

  * GO-2024-3242 CVE-2024-10086 GHSA-99wr-c2px-grmh

  * GO-2024-3243 CVE-2024-10005 GHSA-chgm-7r52-whjj

  * Update to version 0.0.20241101T215616 2024-11-01T21:56:16Z. Refs
      jsc#PED-11136 Go CVE Numbering Authority IDs added or updated with aliases:

  * GO-2024-3244 CVE-2024-50354 GHSA-cph5-3pgr-c82g

  * GO-2024-3245 CVE-2024-39720

  * GO-2024-3246 CVE-2024-8185 GHSA-g233-2p4r-3q7v");

  script_tag(name:"affected", value:"'govulncheck' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"govulncheck-vulndb", rpm:"govulncheck-vulndb~0.0.20241104T154416~150000.1.12.1", rls:"openSUSELeap15.6"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"govulncheck-vulndb", rpm:"govulncheck-vulndb~0.0.20241104T154416~150000.1.12.1", rls:"openSUSELeap15.5"))) {
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
