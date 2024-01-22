# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0294");
  script_cve_id("CVE-2023-4641");
  script_tag(name:"creation_date", value:"2023-10-23 04:11:50 +0000 (Mon, 23 Oct 2023)");
  script_version("2024-01-08T05:05:17+0000");
  script_tag(name:"last_modification", value:"2024-01-08 05:05:17 +0000 (Mon, 08 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-04 17:06:00 +0000 (Thu, 04 Jan 2024)");

  script_name("Mageia: Security Advisory (MGASA-2023-0294)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(8|9)");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0294");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0294.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32285");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20233591-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'shadow-utils' package(s) announced via the MGASA-2023-0294 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix a security vulnerability:

Potential password leak. (CVE-2023-4641)");

  script_tag(name:"affected", value:"'shadow-utils' package(s) on Mageia 8, Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"shadow-utils", rpm:"shadow-utils~4.6~4.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"lib64subid-devel", rpm:"lib64subid-devel~4.13~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64subid4", rpm:"lib64subid4~4.13~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsubid-devel", rpm:"libsubid-devel~4.13~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsubid4", rpm:"libsubid4~4.13~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"shadow-utils", rpm:"shadow-utils~4.13~1.1.mga9", rls:"MAGEIA9"))) {
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
