# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0361");
  script_cve_id("CVE-2014-4607");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-14 15:26:45 +0000 (Fri, 14 Feb 2020)");

  script_name("Mageia: Security Advisory (MGASA-2014-0361)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0361");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0361.html");
  script_xref(name:"URL", value:"http://advisories.mageia.org/MGASA-2014-0290.html");
  script_xref(name:"URL", value:"http://advisories.mageia.org/MGASA-2014-0356.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13944");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14001");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'x11vnc' package(s) announced via the MGASA-2014-0361 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An integer overflow in liblzo before 2.07 allows attackers to cause a
denial of service or possibly code execution in applications using
performing LZO decompression on a compressed payload from the attacker
(CVE-2014-4607).

The libvncserver library is built with a bundled copy of minilzo, which
is a part of liblzo containing the vulnerable code. The remmina package
is built with a bundled copy of libvncserver.

The updated packages should have been shipped along with MGASA-2014-0356");

  script_tag(name:"affected", value:"'x11vnc' package(s) on Mageia 3, Mageia 4.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"x11vnc", rpm:"x11vnc~0.9.13~3.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"x11vnc", rpm:"x11vnc~0.9.13~4.1.mga4", rls:"MAGEIA4"))) {
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
