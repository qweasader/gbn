# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833376");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2022-37966", "CVE-2022-37967", "CVE-2022-38023");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-09 22:15:16 +0000 (Wed, 09 Nov 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:11:44 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for samba (SUSE-SU-2023:0014-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeapMicro5\.2");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0014-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/MBYCGEYBHXXNN4GRDAVVT6OKNJYQ73IL");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba'
  package(s) announced via the SUSE-SU-2023:0014-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for samba fixes the following issues:

     Update to 4.15.13

  - CVE-2022-37966 rc4-hmac Kerberos session keys issued to modern servers
       (bsc#1205385).

  - CVE-2022-37967 Kerberos constrained delegation ticket forgery possible
       against Samba AD DC (bsc#1205386).

  - CVE-2022-38023 RC4/HMAC-MD5 NetLogon Secure Channel is weak and should
       be avoided (bsc#1206504).

  - Fixed issue with bind start up (bsc#1205946).");

  script_tag(name:"affected", value:"'samba' package(s) on openSUSE Leap Micro 5.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs", rpm:"samba-client-libs~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs-debuginfo", rpm:"samba-client-libs-debuginfo~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-debuginfo", rpm:"samba-debuginfo~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-debugsource", rpm:"samba-debugsource~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs", rpm:"samba-client-libs~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs-debuginfo", rpm:"samba-client-libs-debuginfo~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-debuginfo", rpm:"samba-debuginfo~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"openSUSELeapMicro5.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-debugsource", rpm:"samba-debugsource~4.15.13+git.540.fab3b2a46c6~150300.3.46.1", rls:"openSUSELeapMicro5.2"))) {
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