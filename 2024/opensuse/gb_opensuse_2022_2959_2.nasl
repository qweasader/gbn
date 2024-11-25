# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833745");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2022-29154");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-09 18:22:19 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:45:43 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for rsync (SUSE-SU-2022:2959-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeapMicro5\.2");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2959-2");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JNIV6LDUIZCGIUAKCKHK5ZFYTJIJAUSG");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rsync'
  package(s) announced via the SUSE-SU-2022:2959-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rsync fixes the following issues:

  - CVE-2022-29154: Fixed an arbitrary file write issue that could be
       triggered by a malicious remote server (bsc#1201840).");

  script_tag(name:"affected", value:"'rsync' package(s) on openSUSE Leap Micro 5.2.");

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

if(release == "openSUSELeapMicro5.2") {

  if(!isnull(res = isrpmvuln(pkg:"rsync", rpm:"rsync~3.1.3~150000.4.13.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsync-debuginfo", rpm:"rsync-debuginfo~3.1.3~150000.4.13.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsync-debugsource", rpm:"rsync-debugsource~3.1.3~150000.4.13.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsync", rpm:"rsync~3.1.3~150000.4.13.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsync-debuginfo", rpm:"rsync-debuginfo~3.1.3~150000.4.13.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsync-debugsource", rpm:"rsync-debugsource~3.1.3~150000.4.13.1", rls:"openSUSELeapMicro5.2"))) {
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