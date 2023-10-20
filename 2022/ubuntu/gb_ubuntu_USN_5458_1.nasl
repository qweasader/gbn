# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5458.1");
  script_cve_id("CVE-2021-4193", "CVE-2022-0213", "CVE-2022-0319", "CVE-2022-0351", "CVE-2022-0359", "CVE-2022-0361", "CVE-2022-0368", "CVE-2022-0408", "CVE-2022-0443");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2023-06-21T05:06:22+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:22 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-07 19:04:00 +0000 (Mon, 07 Feb 2022)");

  script_name("Ubuntu: Security Advisory (USN-5458-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5458-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5458-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim' package(s) announced via the USN-5458-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Vim was incorrectly handling virtual column
position operations, which could result in an out-of-bounds read. An
attacker could possibly use this issue to expose sensitive
information. (CVE-2021-4193)

It was discovered that Vim was not properly performing bounds checks
when updating windows present on a screen, which could result in a
heap buffer overflow. An attacker could possibly use this issue to
cause a denial of service or execute arbitrary code. (CVE-2022-0213)

It was discovered that Vim was incorrectly handling window
exchanging operations when in Visual mode, which could result in an
out-of-bounds read. An attacker could possibly use this issue to
expose sensitive information. (CVE-2022-0319)

It was discovered that Vim was incorrectly handling recursion when
parsing conditional expressions. An attacker could possibly use this
issue to cause a denial of service or execute arbitrary code.
(CVE-2022-0351)

It was discovered that Vim was not properly handling memory
allocation when processing data in Ex mode, which could result in a
heap buffer overflow. An attacker could possibly use this issue to
cause a denial of service or execute arbitrary code.
(CVE-2022-0359)

It was discovered that Vim was not properly performing bounds checks
when executing line operations in Visual mode, which could result in
a heap buffer overflow. An attacker could possibly use this issue to
cause a denial of service or execute arbitrary code.
(CVE-2022-0361, CVE-2022-0368)

It was discovered that Vim was not properly handling loop conditions
when looking for spell suggestions, which could result in a stack
buffer overflow. An attacker could possibly use this issue to cause
a denial of service or execute arbitrary code. (CVE-2022-0408)

It was discovered that Vim was incorrectly handling memory access
when executing buffer operations, which could result in the usage of
freed memory. An attacker could possibly use this issue to execute
arbitrary code. (CVE-2022-0443)");

  script_tag(name:"affected", value:"'vim' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"vim", ver:"2:7.4.1689-3ubuntu1.5+esm5", rls:"UBUNTU16.04 LTS"))) {
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
