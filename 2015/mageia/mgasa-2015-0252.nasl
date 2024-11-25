# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130124");
  script_cve_id("CVE-2015-1038");
  script_tag(name:"creation_date", value:"2015-10-15 07:43:00 +0000 (Thu, 15 Oct 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2015-0252)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(4|5)");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0252");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0252.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16122");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3289");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'p7zip' package(s) announced via the MGASA-2015-0252 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alexander Cherepanov discovered that p7zip is susceptible to a directory
traversal vulnerability. While extracting an archive, it will extract
symlinks and then follow them if they are referenced in further entries.
This can be exploited by a rogue archive to write files outside the
current directory (CVE-2015-1038).");

  script_tag(name:"affected", value:"'p7zip' package(s) on Mageia 4, Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"p7zip", rpm:"p7zip~9.20.1~4.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"p7zip", rpm:"p7zip~9.20.1~6.1.mga5", rls:"MAGEIA5"))) {
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
