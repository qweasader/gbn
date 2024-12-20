# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0136");
  script_cve_id("CVE-2015-0252");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0136)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0136");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0136.html");
  script_xref(name:"URL", value:"http://xerces.apache.org/xerces-c/secadv/CVE-2015-0252.txt");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15538");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3199");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xerces-c' package(s) announced via the MGASA-2015-0136 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated xerces-c packages fix security vulnerability:

Anton Rager and Jonathan Brossard from the Salesforce.com Product Security
Team and Ben Laurie of Google discovered a denial of service vulnerability in
xerces-c. The parser mishandles certain kinds of malformed input documents,
resulting in a segmentation fault during a parse operation. An
unauthenticated attacker could use this flaw to cause an application using
the xerces-c library to crash (CVE-2015-0252).");

  script_tag(name:"affected", value:"'xerces-c' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"lib64xerces-c-devel", rpm:"lib64xerces-c-devel~3.1.2~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xerces-c3.1", rpm:"lib64xerces-c3.1~3.1.2~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxerces-c-devel", rpm:"libxerces-c-devel~3.1.2~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxerces-c3.1", rpm:"libxerces-c3.1~3.1.2~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xerces-c", rpm:"xerces-c~3.1.2~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xerces-c-doc", rpm:"xerces-c-doc~3.1.2~1.mga4", rls:"MAGEIA4"))) {
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
