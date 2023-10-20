# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845245");
  script_cve_id("CVE-2021-3155", "CVE-2021-4120", "CVE-2021-44730", "CVE-2021-44731");
  script_tag(name:"creation_date", value:"2022-02-18 02:00:25 +0000 (Fri, 18 Feb 2022)");
  script_version("2023-06-21T05:06:22+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:22 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-01 16:56:00 +0000 (Tue, 01 Mar 2022)");

  script_name("Ubuntu: Security Advisory (USN-5292-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|21\.10)");

  script_xref(name:"Advisory-ID", value:"USN-5292-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5292-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'snapd' package(s) announced via the USN-5292-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"James Troup discovered that snap did not properly manage the permissions for
the snap directories. A local attacker could possibly use this issue to expose
sensitive information. (CVE-2021-3155)

Ian Johnson discovered that snapd did not properly validate content interfaces
and layout paths. A local attacker could possibly use this issue to inject
arbitrary AppArmor policy rules, resulting in a bypass of intended access
restrictions. (CVE-2021-4120)

The Qualys Research Team discovered that snapd did not properly validate the
location of the snap-confine binary. A local attacker could possibly use this
issue to execute other arbitrary binaries and escalate privileges.
(CVE-2021-44730)

The Qualys Research Team discovered that a race condition existed in the snapd
snap-confine binary when preparing a private mount namespace for a snap. A
local attacker could possibly use this issue to escalate privileges and
execute arbitrary code. (CVE-2021-44731)");

  script_tag(name:"affected", value:"'snapd' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"snap-confine", ver:"2.54.3+18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"snapd", ver:"2.54.3+18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"snap-confine", ver:"2.54.3+20.04", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"snapd", ver:"2.54.3+20.04", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"snap-confine", ver:"2.54.3+21.10.1", rls:"UBUNTU21.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"snapd", ver:"2.54.3+21.10.1", rls:"UBUNTU21.10"))) {
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
