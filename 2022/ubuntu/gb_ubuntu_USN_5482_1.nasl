# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845415");
  script_cve_id("CVE-2020-28984", "CVE-2021-44118", "CVE-2021-44120", "CVE-2021-44122", "CVE-2021-44123", "CVE-2022-26846", "CVE-2022-26847");
  script_tag(name:"creation_date", value:"2022-06-17 01:00:41 +0000 (Fri, 17 Jun 2022)");
  script_version("2023-06-21T05:06:22+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:22 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-04 15:05:00 +0000 (Thu, 04 Feb 2021)");

  script_name("Ubuntu: Security Advisory (USN-5482-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|21\.10)");

  script_xref(name:"Advisory-ID", value:"USN-5482-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5482-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'spip' package(s) announced via the USN-5482-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that SPIP incorrectly validated inputs. An authenticated
attacker could possibly use this issue to execute arbitrary code.
This issue only affected Ubuntu 18.04 LTS. (CVE-2020-28984)

Charles Fol and Theo Gordyjan discovered that SPIP is vulnerable to Cross
Site Scripting (XSS). If a user were tricked into browsing a malicious SVG
file, an attacker could possibly exploit this issue to execute arbitrary
code. This issue was only fixed in Ubuntu 21.10. (CVE-2021-44118,
CVE-2021-44120, CVE-2021-44122, CVE-2021-44123)

It was discovered that SPIP incorrectly handled certain forms. A remote
authenticated editor could possibly use this issue to execute arbitrary code,
and a remote unauthenticated attacker could possibly use this issue to obtain
sensitive information. (CVE-2022-26846, CVE-2022-26847)");

  script_tag(name:"affected", value:"'spip' package(s) on Ubuntu 18.04, Ubuntu 21.10.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"spip", ver:"3.1.4-4~deb9u5build0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU21.10") {

  if(!isnull(res = isdpkgvuln(pkg:"spip", ver:"3.2.11-3+deb11u3build0.21.10.1", rls:"UBUNTU21.10"))) {
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
