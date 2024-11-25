# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0403");
  script_cve_id("CVE-2022-26495", "CVE-2022-26496");
  script_tag(name:"creation_date", value:"2022-11-02 04:36:04 +0000 (Wed, 02 Nov 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-11 14:37:20 +0000 (Fri, 11 Mar 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0403)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0403");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0403.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30153");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/PU5JFD4PEJED72TZLZ5R2Q2SFXICU5I5/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GY3FXWPGNBOFA2QZOFDFNU2AZJWYEW7A/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5323-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-2944");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5100");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nbd' package(s) announced via the MGASA-2022-0403 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that nbd prior to 3.24 contained an integer overflow
with a resultant heap-based buffer overflow. A value of 0xffffffff in the
name length field will cause a zero-sized buffer to be allocated for the
name resulting in a write to a dangling pointer (CVE-2022-26495).

Stack-based buffer overflow. An attacker can cause a buffer overflow in
the parsing of the name field by sending a crafted NBD_OPT_INFO or
NBD_OPT_GO message with an large value as the length of the name.
(CVE-2022-26496)

Packaging has been adjusted to create the required nbd user and group at
installation.");

  script_tag(name:"affected", value:"'nbd' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"nbd", rpm:"nbd~3.24~1.2.mga8", rls:"MAGEIA8"))) {
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
