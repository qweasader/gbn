# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0337");
  script_cve_id("CVE-2020-15260", "CVE-2021-21375");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-25 13:52:34 +0000 (Thu, 25 Mar 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0337)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0337");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0337.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28998");
  script_xref(name:"URL", value:"https://github.com/pjsip/pjproject/security/advisories/GHSA-8hcp-hm38-mfph");
  script_xref(name:"URL", value:"https://github.com/pjsip/pjproject/security/advisories/GHSA-hvq6-f89p-frvp");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2636");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pjproject' package(s) announced via the MGASA-2021-0337 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Currently, PJSIP transport can be reused if they have the same IP address
+ port + protocol. However, this is insufficient for secure transport since
it lacks remote hostname authentication. The vulnerability allows for an
insecure interaction without user awareness. It affects users who need access
to connections to different destinations that translate to the same address,
and allows man-in-the-middle attack if attacker can route a connection to
another destination such as in the case of DNS spoofing (CVE-2020-15260).

An issue has been found in pjproject. Due to bad handling of two consecutive
crafted answers to an INVITE, the attacker is able to crash the server
resulting in a denial of service (CVE-2021-21375).");

  script_tag(name:"affected", value:"'pjproject' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64pjproject-devel", rpm:"lib64pjproject-devel~2.10~5.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pjproject2", rpm:"lib64pjproject2~2.10~5.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpjproject-devel", rpm:"libpjproject-devel~2.10~5.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpjproject2", rpm:"libpjproject2~2.10~5.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pjproject", rpm:"pjproject~2.10~5.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pjsua", rpm:"pjsua~2.10~5.2.mga8", rls:"MAGEIA8"))) {
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
