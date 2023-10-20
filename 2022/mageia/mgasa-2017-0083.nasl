# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0083");
  script_cve_id("CVE-2017-6307", "CVE-2017-6308", "CVE-2017-6309", "CVE-2017-6310");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-13 17:56:00 +0000 (Wed, 13 Mar 2019)");

  script_name("Mageia: Security Advisory (MGASA-2017-0083)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0083");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0083.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20343");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/02/23/17");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3798");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tnef' package(s) announced via the MGASA-2017-0083 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in tnef before 1.4.13. Two OOB Writes have been
identified in src/mapi_attr.c:mapi_attr_read(). These might lead to
invalid read and write operations, controlled by an attacker.
(CVE-2017-6307)

An issue was discovered in tnef before 1.4.13. Several Integer Overflows,
which can lead to Heap Overflows, have been identified in the functions
that wrap memory allocation. (CVE-2017-6308)

An issue was discovered in tnef before 1.4.13. Two type confusions have
been identified in the parse_file() function. These might lead to invalid
read and write operations, controlled by an attacker. (CVE-2017-6309)

An issue was discovered in tnef before 1.4.13. Four type confusions have
been identified in the file_add_mapi_attrs() function. These might lead to
invalid read and write operations, controlled by an attacker.
(CVE-2017-6310)");

  script_tag(name:"affected", value:"'tnef' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"tnef", rpm:"tnef~1.4.9~4.1.mga5", rls:"MAGEIA5"))) {
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
