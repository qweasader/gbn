# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0093");
  script_cve_id("CVE-2018-20969", "CVE-2019-13636", "CVE-2019-13638");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-16 12:15:00 +0000 (Fri, 16 Aug 2019)");

  script_name("Mageia: Security Advisory (MGASA-2020-0093)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0093");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0093.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25279");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/SVWWGISFWACROJJPVJJL4UBLVZ7LPOLT/");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2019:2798");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'patch' package(s) announced via the MGASA-2020-0093 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated patch package fixes security vulnerabilities:

* In GNU patch through 2.7.6, the following of symlinks is mishandled
 in certain cases other than input files. (CVE-2019-13636).

* A vulnerability was found in GNU patch through 2.7.6 is vulnerable to
 OS shell command injection that can be exploited by opening a crafted
 patch file that contains an ed style diff payload with shell
 metacharacters (CVE-2019-13638).

* A vulnerability was found in do_ed_script in pch.c in GNU patch through
 2.7.6 does not block strings beginning with a ! character. NOTE: this
 is the same commit as for CVE-2019-13638, but the ! syntax is specific to
 ed, and is unrelated to a shell metacharacter (CVE-2018-20969).");

  script_tag(name:"affected", value:"'patch' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"patch", rpm:"patch~2.7.6~4.1.mga7", rls:"MAGEIA7"))) {
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
