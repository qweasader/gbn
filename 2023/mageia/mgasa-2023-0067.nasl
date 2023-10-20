# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0067");
  script_cve_id("CVE-2023-0361");
  script_tag(name:"creation_date", value:"2023-05-23 04:12:36 +0000 (Tue, 23 May 2023)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-23 17:22:00 +0000 (Tue, 23 May 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0067)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0067");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0067.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31558");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5349");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3321");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls' package(s) announced via the MGASA-2023-0067 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Timing side channel in the RSA decryption implementation of the GNU TLS
library. (CVE-2023-0361)");

  script_tag(name:"affected", value:"'gnutls' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~3.6.15~3.4.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gnutls-devel", rpm:"lib64gnutls-devel~3.6.15~3.4.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gnutls30", rpm:"lib64gnutls30~3.6.15~3.4.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gnutlsxx28", rpm:"lib64gnutlsxx28~3.6.15~3.4.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls-devel", rpm:"libgnutls-devel~3.6.15~3.4.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30", rpm:"libgnutls30~3.6.15~3.4.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutlsxx28", rpm:"libgnutlsxx28~3.6.15~3.4.mga8", rls:"MAGEIA8"))) {
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
