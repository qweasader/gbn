# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0786.1");
  script_cve_id("CVE-2021-40633", "CVE-2022-28506", "CVE-2023-48161");
  script_tag(name:"creation_date", value:"2024-03-08 04:22:27 +0000 (Fri, 08 Mar 2024)");
  script_version("2024-03-08T15:37:10+0000");
  script_tag(name:"last_modification", value:"2024-03-08 15:37:10 +0000 (Fri, 08 Mar 2024)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-23 14:20:26 +0000 (Thu, 23 Jun 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0786-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0786-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240786-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'giflib' package(s) announced via the SUSE-SU-2024:0786-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for giflib fixes the following issues:
Update to version 5.2.2

Fixes for CVE-2023-48161 (bsc#1217390), CVE-2022-28506 (bsc#1198880)

138 Documentation for obsolete utilities still installed


139: Typo in 'LZW image data' page ('110_2 = 4_10')


140: Typo in 'LZW image data' page ('LWZ')


141: Typo in 'Bits and bytes' page ('filed')

Note as already fixed SF issue #143: cannot compile under mingw

144: giflib-5.2.1 cannot be build on windows and other platforms using c89


145: Remove manual pages installation for binaries that are not installed too


146: [PATCH] Limit installed man pages to binaries, move giflib to section 7


147 [PATCH] Fixes to doc/whatsinagif/ content


148: heap Out of Bound Read in gif2rgb.c:298 DumpScreen2RGB

Declared no-info on SF issue #150: There is a denial of service vulnerability in GIFLIB 5.2.1 Declared Won't-fix on SF issue 149: Out of source builds no longer possible

151: A heap-buffer-overflow in gif2rgb.c:294:45


152: Fix some typos on the html documentation and man pages


153: Fix segmentation faults due to non correct checking for args


154: Recover the giffilter manual page


155: Add gifsponge docs


157: An OutofMemory-Exception or Memory Leak in gif2rgb


158: There is a null pointer problem in gif2rgb


159 A heap-buffer-overflow in GIFLIB5.2.1 DumpScreen2RGB() in gif2rgb.c:298:45


163: detected memory leaks in openbsd_reallocarray giflib/openbsd-reallocarray.c


164: detected memory leaks in GifMakeMapObject giflib/gifalloc.c


166: a read zero page leads segment fault in getarg.c and memory leaks in gif2rgb.c and gifmalloc.c


167: Heap-Buffer Overflow during Image Saving in DumpScreen2RGB Function at Line 321 of gif2rgb.c");

  script_tag(name:"affected", value:"'giflib' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise Desktop 15-SP4, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise High Performance Computing 15-SP4, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Manager Proxy 4.3, SUSE Manager Retail Branch Server 4.3, SUSE Manager Server 4.3.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"giflib-debugsource", rpm:"giflib-debugsource~5.2.2~150000.4.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"giflib-devel", rpm:"giflib-devel~5.2.2~150000.4.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgif7", rpm:"libgif7~5.2.2~150000.4.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgif7-debuginfo", rpm:"libgif7-debuginfo~5.2.2~150000.4.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"giflib-debugsource", rpm:"giflib-debugsource~5.2.2~150000.4.13.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"giflib-devel", rpm:"giflib-devel~5.2.2~150000.4.13.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgif7", rpm:"libgif7~5.2.2~150000.4.13.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgif7-debuginfo", rpm:"libgif7-debuginfo~5.2.2~150000.4.13.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"giflib-debugsource", rpm:"giflib-debugsource~5.2.2~150000.4.13.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"giflib-devel", rpm:"giflib-devel~5.2.2~150000.4.13.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgif7", rpm:"libgif7~5.2.2~150000.4.13.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgif7-debuginfo", rpm:"libgif7-debuginfo~5.2.2~150000.4.13.1", rls:"SLES15.0SP4"))) {
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
