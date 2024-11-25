# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0328");
  script_cve_id("CVE-2020-6624", "CVE-2020-6625", "CVE-2021-3496");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-27 19:52:39 +0000 (Tue, 27 Apr 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0328)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0328");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0328.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29053");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JPTEPBJVJFSKKHSTZER2JVIMRP7MGN2C/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/SCW5XBSBEM6OUDLCSLS5UW7BSRNESS4J/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jhead' package(s) announced via the MGASA-2021-0328 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated jhead package fixes security vulnerabilities:

jhead through 3.04 has a heap-based buffer over-read in process_DQT in
jpgqguess.c (CVE-2020-6624).

jhead through 3.04 has a heap-based buffer over-read in Get32s when called
from ProcessGpsInfo in gpsinfo.c (CVE-2020-6625).

A heap-based buffer overflow was found in jhead in version 3.06 in Get16u()
in exif.c when processing a crafted file (CVE-2021-3496).");

  script_tag(name:"affected", value:"'jhead' package(s) on Mageia 7, Mageia 8.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"jhead", rpm:"jhead~3.06.0.1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"jhead", rpm:"jhead~3.06.0.1~1.mga8", rls:"MAGEIA8"))) {
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
