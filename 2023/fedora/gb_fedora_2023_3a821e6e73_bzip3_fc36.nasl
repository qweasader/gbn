# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.827508");
  script_version("2023-10-12T05:05:32+0000");
  script_cve_id("CVE-2023-29415", "CVE-2023-29416", "CVE-2023-29417", "CVE-2023-29418", "CVE-2023-29419", "CVE-2023-29420", "CVE-2023-29421");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-12 17:12:00 +0000 (Wed, 12 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-15 01:06:45 +0000 (Sat, 15 Apr 2023)");
  script_name("Fedora: Security Advisory for bzip3 (FEDORA-2023-3a821e6e73)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC36");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-3a821e6e73");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/NA7S7HDUAINOTCSWQZ5LIW756DYY22V2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bzip3'
  package(s) announced via the FEDORA-2023-3a821e6e73 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"These are tools for compressing, decompressing, printing, and searching bzip3
files. bzip3 features higher compression ratios and better performance than
bzip2 thanks to an order-0 context mixing entropy coder, a fast
Burrows-Wheeler transform code making use of suffix arrays and a run-length
encoding with Lempel-Ziv prediction pass based on LZ77-style string matching
and PPM-style context modeling.");

  script_tag(name:"affected", value:"'bzip3' package(s) on Fedora 36.");

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

if(release == "FC36") {

  if(!isnull(res = isrpmvuln(pkg:"bzip3", rpm:"bzip3~1.3.0~1.fc36", rls:"FC36"))) {
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