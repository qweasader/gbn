# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0371");
  script_cve_id("CVE-2021-4217", "CVE-2022-0529", "CVE-2022-0530");
  script_tag(name:"creation_date", value:"2022-10-19 04:46:32 +0000 (Wed, 19 Oct 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-04 17:06:44 +0000 (Wed, 04 May 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0371)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0371");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0371.html");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/ubuntu/+source/unzip/+bug/1957077");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29893");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2044583");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2051395");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2051402");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/VFUXYMOCMRAV3GMQQKYX6T4L2I23XSQU/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5673-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3118");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5202");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'unzip' package(s) announced via the MGASA-2022-0371 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Improper handling of Unicode strings, which can lead to a null pointer
dereference. This flaw allows an attacker to input a specially crafted zip
file, leading to a crash or code execution. (CVE-2021-4217)

Conversion of a wide string to a local string that leads to a heap of
out-of-bound write. This flaw allows an attacker to input a specially
crafted zip file, leading to a crash or code execution. (CVE-2022-0529,
CVE-2022-0530)");

  script_tag(name:"affected", value:"'unzip' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"unzip", rpm:"unzip~6.0~2.1.mga8", rls:"MAGEIA8"))) {
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
