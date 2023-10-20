# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0235");
  script_tag(name:"creation_date", value:"2022-06-20 04:29:41 +0000 (Mon, 20 Jun 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2022-0235)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0235");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0235.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30556");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5481-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bluez' package(s) announced via the MGASA-2022-0235 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that BlueZ incorrectly validated certain capabilities
and lengths when handling the A2DP profile. A remote attacker could use
this issue to cause BlueZ to crash, resulting in a denial of service, or
possibly execute arbitrary code.");

  script_tag(name:"affected", value:"'bluez' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"bluez", rpm:"bluez~5.55~3.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-cups", rpm:"bluez-cups~5.55~3.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-hid2hci", rpm:"bluez-hid2hci~5.55~3.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-mesh", rpm:"bluez-mesh~5.55~3.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bluez-devel", rpm:"lib64bluez-devel~5.55~3.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bluez3", rpm:"lib64bluez3~5.55~3.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbluez-devel", rpm:"libbluez-devel~5.55~3.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbluez3", rpm:"libbluez3~5.55~3.5.mga8", rls:"MAGEIA8"))) {
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
