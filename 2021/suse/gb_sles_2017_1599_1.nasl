# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1599.1");
  script_cve_id("CVE-2014-9846", "CVE-2016-10050", "CVE-2017-7606", "CVE-2017-7941", "CVE-2017-7942", "CVE-2017-7943", "CVE-2017-8344", "CVE-2017-8345", "CVE-2017-8346", "CVE-2017-8348", "CVE-2017-8349", "CVE-2017-8350", "CVE-2017-8351", "CVE-2017-8352", "CVE-2017-8353", "CVE-2017-8354", "CVE-2017-8355", "CVE-2017-8357", "CVE-2017-8765", "CVE-2017-8830", "CVE-2017-9098", "CVE-2017-9141", "CVE-2017-9142", "CVE-2017-9143", "CVE-2017-9144");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:55 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:49+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:49 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-22 19:03:29 +0000 (Wed, 22 Mar 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1599-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1599-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171599-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2017:1599-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ImageMagick fixes the following issues:
This security issue was fixed:
- CVE-2017-7941: The ReadSGIImage function in sgi.c allowed remote
 attackers to consume an amount of available memory via a crafted file
 (bsc#1034876).
- CVE-2017-8351: ImageMagick, GraphicsMagick: denial of service (memory
 leak) via a crafted file (ReadPCDImage func in pcd.c) (bsc#1036986).
- CVE-2017-8352: denial of service (memory leak) via a crafted file
 (ReadXWDImage func in xwd.c) (bsc#1036987)
- CVE-2017-8349: denial of service (memory leak) via a crafted file
 (ReadSFWImage func in sfw.c) (bsc#1036984)
- CVE-2017-8350: denial of service (memory leak) via a crafted file
 (ReadJNGImage function in png.c) (bsc#1036985)
- CVE-2017-8345: denial of service (memory leak) via a crafted file
 (ReadMNGImage func in png.c) (bsc#1036980)
- CVE-2017-8346: denial of service (memory leak) via a crafted file
 (ReadDCMImage func in dcm.c) (bsc#1036981)
- CVE-2017-8353: denial of service (memory leak) via a crafted file
 (ReadPICTImage func in pict.c) (bsc#1036988)
- CVE-2017-8830: denial of service (memory leak) via a crafted file
 (ReadBMPImage func in bmp.c:1379) (bsc#1038000)
- CVE-2017-7606: denial of service (application crash) or possibly have
 unspecified other impact via a crafted image (bsc#1033091)
- CVE-2017-8765: memory leak vulnerability via a crafted ICON file
 (ReadICONImage in coders\icon.c) (bsc#1037527)
- CVE-2017-8355: denial of service (memory leak) via a crafted file
 (ReadMTVImage func in mtv.c) (bsc#1036990)
- CVE-2017-8344: denial of service (memory leak) via a crafted file
 (ReadPCXImage func in pcx.c) (bsc#1036978)
- CVE-2017-9098: uninitialized memory usage in the ReadRLEImage RLE
 decoder function coders/rle.c (bsc#1040025)
- CVE-2017-9141: Missing checks in the ReadDDSImage function in
 coders/dds.c could lead to a denial of service (assertion) (bsc#1040303)
- CVE-2017-9142: Missing checks in theReadOneJNGImage function in
 coders/png.c could lead to denial of service (assertion) (bsc#1040304)
- CVE-2017-9143: A possible denial of service attack via crafted .art file
 in ReadARTImage function in coders/art.c (bsc#1040306)
- CVE-2017-9144: A crafted RLE image can trigger a crash in coders/rle.c
 could lead to a denial of service (crash) (bsc#1040332)");

  script_tag(name:"affected", value:"'ImageMagick' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore1-32bit", rpm:"libMagickCore1-32bit~6.4.3.6~7.77.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libMagickCore1", rpm:"libMagickCore1~6.4.3.6~7.77.1", rls:"SLES11.0SP4"))) {
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
