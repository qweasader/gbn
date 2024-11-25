# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0110");
  script_cve_id("CVE-2020-29050");
  script_tag(name:"creation_date", value:"2022-03-24 04:13:35 +0000 (Thu, 24 Mar 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-14 16:03:34 +0000 (Fri, 14 Jan 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0110)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0110");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0110.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30076");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/BGIIYJ6U7AIFKGIYHMGJHVDPJF5AWYOA/");
  script_xref(name:"URL", value:"https://salsa.debian.org/debian/sphinxsearch/-/blob/4d6fe40644130308604845db43d3588e715ec85d/debian/patches/06-CVE-2020-29050.patch");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5036");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sphinx' package(s) announced via the MGASA-2022-0110 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that sphinx could allow arbitrary files to be read by abusing
a configuration option. (CVE-2020-29050)");

  script_tag(name:"affected", value:"'sphinx' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"lib64sphinxclient-devel", rpm:"lib64sphinxclient-devel~2.3.2~0.beta.3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sphinxclient1", rpm:"lib64sphinxclient1~2.3.2~0.beta.3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsphinxclient-devel", rpm:"libsphinxclient-devel~2.3.2~0.beta.3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsphinxclient1", rpm:"libsphinxclient1~2.3.2~0.beta.3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sphinx", rpm:"sphinx~2.3.2~0.beta.3.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sphinx-java", rpm:"sphinx-java~2.3.2~0.beta.3.1.mga8", rls:"MAGEIA8"))) {
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
