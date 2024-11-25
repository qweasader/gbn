# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0428");
  script_cve_id("CVE-2020-10108", "CVE-2020-10109");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-12 16:34:59 +0000 (Thu, 12 Mar 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0428)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0428");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0428.html");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2020:1561");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26355");
  script_xref(name:"URL", value:"https://know.bishopfox.com/advisories/twisted-version-19.10.0");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/YW3NIL7VXSGJND2Q4BSXM3CFTAFU6T7D/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4308-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2145");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-twisted' package(s) announced via the MGASA-2020-0428 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jake Miller and ZeddYu Lu discovered that Twisted incorrectly handled certain
content-length headers. A remote attacker could possibly use this issue to
perform HTTP request splitting attacks (CVE-2020-10108, CVE-2020-10109).");

  script_tag(name:"affected", value:"'python-twisted' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-twisted", rpm:"python-twisted~19.2.1~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-twisted", rpm:"python2-twisted~19.2.1~1.2.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-twisted", rpm:"python3-twisted~19.2.1~1.2.mga7", rls:"MAGEIA7"))) {
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
