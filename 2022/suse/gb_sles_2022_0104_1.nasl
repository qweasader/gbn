# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.0104.1");
  script_cve_id("CVE-2020-14409", "CVE-2020-14410");
  script_tag(name:"creation_date", value:"2022-01-20 07:39:58 +0000 (Thu, 20 Jan 2022)");
  script_version("2024-02-02T14:37:51+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:51 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-22 15:24:01 +0000 (Fri, 22 Jan 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:0104-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:0104-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20220104-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SDL2' package(s) announced via the SUSE-SU-2022:0104-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for SDL2 fixes the following issues:

CVE-2020-14409: Fixed Integer Overflow resulting in heap corruption in
 SDL_BlitCopy in video/SDL_blit_copy.c via a crafted .BMP (bsc#1181202).

CVE-2020-14410: Fixed heap-based buffer over-read in
 Blit_3or4_to_3or4__inversed_rgb in video/SDL_blit_N.c via a crafted .BMP
 (bsc#1181201).");

  script_tag(name:"affected", value:"'SDL2' package(s) on SUSE Enterprise Storage 7, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise Module for Desktop Applications 15-SP3, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP3, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP 15-SP2, SUSE Manager Proxy 4.1, SUSE Manager Retail Branch Server 4.1, SUSE Manager Server 4.1.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"SDL2-debugsource", rpm:"SDL2-debugsource~2.0.8~11.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL2-2_0-0", rpm:"libSDL2-2_0-0~2.0.8~11.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL2-2_0-0-debuginfo", rpm:"libSDL2-2_0-0-debuginfo~2.0.8~11.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL2-devel", rpm:"libSDL2-devel~2.0.8~11.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL2-2_0-0-32bit", rpm:"libSDL2-2_0-0-32bit~2.0.8~11.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL2-2_0-0-32bit-debuginfo", rpm:"libSDL2-2_0-0-32bit-debuginfo~2.0.8~11.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"SDL2-debugsource", rpm:"SDL2-debugsource~2.0.8~11.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL2-2_0-0", rpm:"libSDL2-2_0-0~2.0.8~11.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL2-2_0-0-debuginfo", rpm:"libSDL2-2_0-0-debuginfo~2.0.8~11.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL2-devel", rpm:"libSDL2-devel~2.0.8~11.3.1", rls:"SLES15.0SP2"))) {
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
