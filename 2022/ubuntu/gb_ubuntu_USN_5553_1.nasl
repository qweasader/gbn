# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5553.1");
  script_cve_id("CVE-2018-11813", "CVE-2018-14498", "CVE-2020-14152", "CVE-2020-17541");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2023-06-21T05:06:22+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:22 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 15:21:00 +0000 (Mon, 14 Jun 2021)");

  script_name("Ubuntu: Security Advisory (USN-5553-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5553-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5553-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libjpeg-turbo' package(s) announced via the USN-5553-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libjpeg-turbo was not properly handling EOF characters,
which could lead to excessive memory consumption through the execution of a
large loop. An attacker could possibly use this issue to cause a denial of
service. (CVE-2018-11813)

It was discovered that libjpeg-turbo was not properly performing bounds
check operations, which could lead to a heap-based buffer overread. If a user
or automated system were tricked into opening a specially crafted file, an
attacker could possibly use this issue to cause a denial of service. This
issue only affected Ubuntu 14.04 ESM. (CVE-2018-14498)

It was discovered that libjpeg-turbo was not properly limiting the amount of
main memory being consumed by the system during decompression or multi-pass
compression operations, which could lead to excessive memory consumption. An
attacker could possibly use this issue to cause a denial of service.
(CVE-2020-14152)

It was discovered that libjpeg-turbo was not properly setting variable sizes
when performing certain kinds of encoding operations, which could lead to a
stack-based buffer overflow. If a user or automated system were tricked into
opening a specially crafted file, an attacker could possibly use this issue to
cause a denial of service. (CVE-2020-17541)");

  script_tag(name:"affected", value:"'libjpeg-turbo' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libjpeg-turbo-progs", ver:"1.3.0-0ubuntu2.1+esm2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjpeg-turbo-test", ver:"1.3.0-0ubuntu2.1+esm2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjpeg-turbo8", ver:"1.3.0-0ubuntu2.1+esm2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libturbojpeg", ver:"1.3.0-0ubuntu2.1+esm2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libjpeg-turbo-progs", ver:"1.4.2-0ubuntu3.4+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjpeg-turbo-test", ver:"1.4.2-0ubuntu3.4+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjpeg-turbo8", ver:"1.4.2-0ubuntu3.4+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libturbojpeg", ver:"1.4.2-0ubuntu3.4+esm1", rls:"UBUNTU16.04 LTS"))) {
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
