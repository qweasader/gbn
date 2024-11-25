# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856124");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2024-32039", "CVE-2024-32040", "CVE-2024-32041", "CVE-2024-32458", "CVE-2024-32459", "CVE-2024-32460");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"creation_date", value:"2024-05-13 01:00:34 +0000 (Mon, 13 May 2024)");
  script_name("openSUSE: Security Advisory for freerdp (SUSE-SU-2024:1610-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1610-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/VPTWVBD3OLCPCVVLQRAJACJYM2LIQFLF");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp'
  package(s) announced via the SUSE-SU-2024:1610-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for freerdp fixes the following issues:

  * CVE-2024-32039: Fixed an out-of-bounds write with variables of type uint32
      (bsc#1223293)

  * CVE-2024-32040: Fixed a integer underflow when using the 'NSC' codec
      (bsc#1223294)

  * CVE-2024-32041: Fixed an out-of-bounds read in Stream_GetRemainingLength()
      (bsc#1223295)

  * CVE-2024-32458: Fixed an out-of-bounds read on pSrcData[] (bsc#1223296)

  * CVE-2024-32459: Fixed an out-of-bounds read in case SrcSize less than 4
      (bsc#1223297)

  * CVE-2024-32460: Fixed an out-of-bounds read when using '/bpp:32' legacy
      'GDI' drawing path (bsc#1223298)

  ##");

  script_tag(name:"affected", value:"'freerdp' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"freerdp-debugsource", rpm:"freerdp-debugsource~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp2", rpm:"libfreerdp2~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-server-debuginfo", rpm:"freerdp-server-debuginfo~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr2-debuginfo", rpm:"libwinpr2-debuginfo~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuwac0-0", rpm:"libuwac0-0~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-debuginfo", rpm:"freerdp-debuginfo~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"winpr2-devel", rpm:"winpr2-devel~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-wayland", rpm:"freerdp-wayland~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuwac0-0-debuginfo", rpm:"libuwac0-0-debuginfo~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-proxy", rpm:"freerdp-proxy~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-server", rpm:"freerdp-server~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-wayland-debuginfo", rpm:"freerdp-wayland-debuginfo~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr2", rpm:"libwinpr2~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp2-debuginfo", rpm:"libfreerdp2-debuginfo~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-devel", rpm:"freerdp-devel~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-proxy-debuginfo", rpm:"freerdp-proxy-debuginfo~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwac0-0-devel", rpm:"uwac0-0-devel~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-debugsource", rpm:"freerdp-debugsource~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp2", rpm:"libfreerdp2~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-server-debuginfo", rpm:"freerdp-server-debuginfo~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr2-debuginfo", rpm:"libwinpr2-debuginfo~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuwac0-0", rpm:"libuwac0-0~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-debuginfo", rpm:"freerdp-debuginfo~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"winpr2-devel", rpm:"winpr2-devel~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-wayland", rpm:"freerdp-wayland~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuwac0-0-debuginfo", rpm:"libuwac0-0-debuginfo~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-proxy", rpm:"freerdp-proxy~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-server", rpm:"freerdp-server~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-wayland-debuginfo", rpm:"freerdp-wayland-debuginfo~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr2", rpm:"libwinpr2~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp2-debuginfo", rpm:"libfreerdp2-debuginfo~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-devel", rpm:"freerdp-devel~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-proxy-debuginfo", rpm:"freerdp-proxy-debuginfo~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwac0-0-devel", rpm:"uwac0-0-devel~2.4.0~150400.3.29.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"freerdp-debugsource", rpm:"freerdp-debugsource~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp2", rpm:"libfreerdp2~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-server-debuginfo", rpm:"freerdp-server-debuginfo~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr2-debuginfo", rpm:"libwinpr2-debuginfo~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuwac0-0", rpm:"libuwac0-0~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-debuginfo", rpm:"freerdp-debuginfo~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"winpr2-devel", rpm:"winpr2-devel~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-wayland", rpm:"freerdp-wayland~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuwac0-0-debuginfo", rpm:"libuwac0-0-debuginfo~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-proxy", rpm:"freerdp-proxy~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-server", rpm:"freerdp-server~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-wayland-debuginfo", rpm:"freerdp-wayland-debuginfo~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr2", rpm:"libwinpr2~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp2-debuginfo", rpm:"libfreerdp2-debuginfo~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-devel", rpm:"freerdp-devel~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-proxy-debuginfo", rpm:"freerdp-proxy-debuginfo~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwac0-0-devel", rpm:"uwac0-0-devel~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-debugsource", rpm:"freerdp-debugsource~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp2", rpm:"libfreerdp2~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-server-debuginfo", rpm:"freerdp-server-debuginfo~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr2-debuginfo", rpm:"libwinpr2-debuginfo~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuwac0-0", rpm:"libuwac0-0~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-debuginfo", rpm:"freerdp-debuginfo~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"winpr2-devel", rpm:"winpr2-devel~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-wayland", rpm:"freerdp-wayland~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuwac0-0-debuginfo", rpm:"libuwac0-0-debuginfo~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-proxy", rpm:"freerdp-proxy~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-server", rpm:"freerdp-server~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-wayland-debuginfo", rpm:"freerdp-wayland-debuginfo~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr2", rpm:"libwinpr2~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp2-debuginfo", rpm:"libfreerdp2-debuginfo~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-devel", rpm:"freerdp-devel~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-proxy-debuginfo", rpm:"freerdp-proxy-debuginfo~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwac0-0-devel", rpm:"uwac0-0-devel~2.4.0~150400.3.29.1", rls:"openSUSELeap15.5"))) {
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