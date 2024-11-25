# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0187");
  script_cve_id("CVE-2022-20770", "CVE-2022-20771", "CVE-2022-20785", "CVE-2022-20792", "CVE-2022-20796");
  script_tag(name:"creation_date", value:"2022-05-19 07:28:20 +0000 (Thu, 19 May 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-12 17:58:45 +0000 (Fri, 12 Aug 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0187)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0187");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0187.html");
  script_xref(name:"URL", value:"https://blog.clamav.net/2022/05/clamav-01050-01043-01036-released.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30417");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OQIRF7L5ZKGSRUC6DDORCDJYKMVJMCEB/");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221647-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav' package(s) announced via the MGASA-2022-0187 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Infinite loop vulnerability in the CHM file parser. Issue affects versions
0.104.0 through 0.104.2 and LTS version 0.103.5 and prior versions.
(CVE-2022-20770)

Infinite loop vulnerability in the TIFF file parser. Issue affects versions
0.104.0 through 0.104.2 and LTS version 0.103.5 and prior versions. The
issue only occurs if the '--alert-broken-media' ClamScan option is enabled.
For ClamD, the affected option is 'AlertBrokenMedia yes', and for libclamav
it is the 'CL_SCAN_HEURISTIC_BROKEN_MEDIA' scan option. (CVE-2022-20771)

Memory leak in the HTML file parser / Javascript normalizer. Issue affects
versions 0.104.0 through 0.104.2 and LTS version 0.103.5 and prior
versions. (CVE-2022-20785)

Multi-byte heap buffer overflow write vulnerability in the signature
database load module. The fix was to update the vendored regex library to
the latest version. Issue affects versions 0.104.0 through 0.104.2 and LTS
version 0.103.5 and prior versions. (CVE-2022-20792)

NULL-pointer dereference crash in the scan verdict cache check. Issue
affects versions 0.103.4, 0.103.5, 0.104.1, and 0.104.2. (CVE-2022-20796)");

  script_tag(name:"affected", value:"'clamav' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.103.6~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-db", rpm:"clamav-db~0.103.6~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-milter", rpm:"clamav-milter~0.103.6~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamd", rpm:"clamd~0.103.6~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64clamav-devel", rpm:"lib64clamav-devel~0.103.6~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64clamav9", rpm:"lib64clamav9~0.103.6~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav-devel", rpm:"libclamav-devel~0.103.6~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav9", rpm:"libclamav9~0.103.6~1.mga8", rls:"MAGEIA8"))) {
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
