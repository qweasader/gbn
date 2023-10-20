# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0259");
  script_cve_id("CVE-2021-22204");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-16 12:15:00 +0000 (Sun, 16 May 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0259)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0259");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0259.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28927");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2021/05/09/1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DDKDLJLBTBBR66OOPXSXCG2PQRM5KCZL/");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4910");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/SLQ4XG6SNL6OL7SHPBZLVWYCAEZGZW5X/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-Image-ExifTool' package(s) announced via the MGASA-2021-0259 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Improper neutralization of user data in the DjVu file format in ExifTool
versions 7.44 and up allows arbitrary code execution when parsing the
malicious image (CVE-2021-22204).");

  script_tag(name:"affected", value:"'perl-Image-ExifTool' package(s) on Mageia 7, Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"perl-Image-ExifTool", rpm:"perl-Image-ExifTool~11.300.0~1.1.mga7", rls:"MAGEIA7"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"perl-Image-ExifTool", rpm:"perl-Image-ExifTool~12.0.0~1.1.mga8", rls:"MAGEIA8"))) {
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
