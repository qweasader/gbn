# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2019.2357");
  script_cve_id("CVE-2011-2895", "CVE-2017-13720", "CVE-2017-13722", "CVE-2017-16611");
  script_tag(name:"creation_date", value:"2020-01-23 12:51:11 +0000 (Thu, 23 Jan 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-13 02:29:00 +0000 (Mon, 13 Nov 2017)");

  script_name("Huawei EulerOS: Security Advisory for libXfont (EulerOS-SA-2019-2357)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2019-2357");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2357");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libXfont' package(s) announced via the EulerOS-SA-2019-2357 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The LZW decompressor in (1) the BufCompressedFill function in fontfile/decompress.c in X.Org libXfont before 1.4.4 and (2) compress/compress.c in 4.3BSD, as used in zopen.c in OpenBSD before 3.8, FreeBSD, NetBSD 4.0.x and 5.0.x before 5.0.3 and 5.1.x before 5.1.1, FreeType 2.1.9, and other products, does not properly handle code words that are absent from the decompression table when encountered, which allows context-dependent attackers to trigger an infinite loop or a heap-based buffer overflow, and possibly execute arbitrary code, via a crafted compressed stream, a related issue to CVE-2006-1168 and CVE-2011-2896.(CVE-2011-2895)

In the pcfGetProperties function in bitmap/pcfread.c in libXfont through 1.5.2 and 2.x before 2.0.2, a missing boundary check (for PCF files) could be used by local attackers authenticated to an Xserver for a buffer over-read, for information disclosure or a crash of the X server.(CVE-2017-13722)

In the PatternMatch function in fontfile/fontdir.c in libXfont through 1.5.2 and 2.x before 2.0.2, an attacker with access to an X connection can cause a buffer over-read during pattern matching of fonts, leading to information disclosure or a crash (denial of service). This occurs because '\0' characters are incorrectly skipped in situations involving ? characters.(CVE-2017-13720)

In libXfont before 1.5.4 and libXfont2 before 2.0.3, a local attacker can open (but not read) files on the system as root, triggering tape rewinds, watchdogs, or similar mechanisms that can be triggered by opening files.(CVE-2017-16611)");

  script_tag(name:"affected", value:"'libXfont' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libXfont", rpm:"libXfont~1.5.1~2.h2", rls:"EULEROS-2.0SP2"))) {
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
