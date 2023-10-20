# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0451");
  script_cve_id("CVE-2014-10402");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-02 16:13:00 +0000 (Fri, 02 Oct 2020)");

  script_name("Mageia: Security Advisory (MGASA-2021-0451)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0451");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0451.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29327");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5030-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-DBI' package(s) announced via the MGASA-2021-0451 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in the DBI module through 1.643 for Perl.
DBD::File drivers can open files from folders other than those
specifically passed via the f_dir attribute in the data source name (DSN).
(CVE-2014-10402)");

  script_tag(name:"affected", value:"'perl-DBI' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"perl-DBI", rpm:"perl-DBI~1.643.0~4.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-DBI-ProfileDumper-Apache", rpm:"perl-DBI-ProfileDumper-Apache~1.643.0~4.1.mga8", rls:"MAGEIA8"))) {
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
