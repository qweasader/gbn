# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0342");
  script_cve_id("CVE-2020-15890");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-04 17:36:34 +0000 (Tue, 04 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0342)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0342");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0342.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27021");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2296");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'luajit' package(s) announced via the MGASA-2020-0342 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue has been found in luajit, a just in time compiler for Lua.
An out-of-bounds read could happen because __gc handler frame traversal
is mishandled (CVE-2020-15890).");

  script_tag(name:"affected", value:"'luajit' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64luajit5.1-devel", rpm:"lib64luajit5.1-devel~2.1.0~0.beta3.5.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64luajit5.1_2", rpm:"lib64luajit5.1_2~2.1.0~0.beta3.5.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libluajit5.1-devel", rpm:"libluajit5.1-devel~2.1.0~0.beta3.5.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libluajit5.1_2", rpm:"libluajit5.1_2~2.1.0~0.beta3.5.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"luajit", rpm:"luajit~2.1.0~0.beta3.5.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"luajit-common", rpm:"luajit-common~2.1.0~0.beta3.5.mga7", rls:"MAGEIA7"))) {
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
