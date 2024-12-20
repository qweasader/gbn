# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843827");
  script_cve_id("CVE-2018-6954");
  script_tag(name:"creation_date", value:"2018-11-20 05:00:40 +0000 (Tue, 20 Nov 2018)");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-16 13:36:35 +0000 (Fri, 16 Mar 2018)");

  script_name("Ubuntu: Security Advisory (USN-3816-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|18\.10)");

  script_xref(name:"Advisory-ID", value:"USN-3816-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3816-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd' package(s) announced via the USN-3816-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3816-1 fixed several vulnerabilities in systemd. However, the fix for
CVE-2018-6954 was not sufficient. This update provides the remaining fixes.

We apologize for the inconvenience.

Original advisory details:

 Jann Horn discovered that unit_deserialize incorrectly handled status messages
 above a certain length. A local attacker could potentially exploit this via
 NotifyAccess to inject arbitrary state across re-execution and obtain root
 privileges. (CVE-2018-15686)

 Jann Horn discovered a race condition in chown_one(). A local attacker
 could potentially exploit this by setting arbitrary permissions on certain
 files to obtain root privileges. This issue only affected Ubuntu 18.04 LTS
 and Ubuntu 18.10. (CVE-2018-15687)

 It was discovered that systemd-tmpfiles mishandled symlinks in
 non-terminal path components. A local attacker could potentially exploit
 this by gaining ownership of certain files to obtain root privileges. This
 issue only affected Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. (CVE-2018-6954)");

  script_tag(name:"affected", value:"'systemd' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 18.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"systemd", ver:"229-4ubuntu21.9", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"systemd", ver:"237-3ubuntu10.9", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.10") {

  if(!isnull(res = isdpkgvuln(pkg:"systemd", ver:"239-7ubuntu10.4", rls:"UBUNTU18.10"))) {
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
