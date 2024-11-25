# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2019.4171.2");
  script_cve_id("CVE-2019-11481", "CVE-2019-11482", "CVE-2019-11483", "CVE-2019-11485", "CVE-2019-15790");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-12 21:21:33 +0000 (Wed, 12 Feb 2020)");

  script_name("Ubuntu: Security Advisory (USN-4171-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-4171-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4171-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apport' package(s) announced via the USN-4171-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4171-1 fixed several vulnerabilities in apport. This update provides
the corresponding update for Ubuntu 14.04 ESM.

Original advisory details:

 Kevin Backhouse discovered Apport would read its user-controlled settings
 file as the root user. This could be used by a local attacker to possibly
 crash Apport or have other unspecified consequences. (CVE-2019-11481)

 Sander Bos discovered a race-condition in Apport during core dump
 creation. This could be used by a local attacker to generate a crash report
 for a privileged process that is readable by an unprivileged user.
 (CVE-2019-11482)

 Sander Bos discovered Apport mishandled crash dumps originating from
 containers. This could be used by a local attacker to generate a crash
 report for a privileged process that is readable by an unprivileged user.
 (CVE-2019-11483)

 Sander Bos discovered Apport mishandled lock-file creation. This could be
 used by a local attacker to cause a denial of service against Apport.
 (CVE-2019-11485)

 Kevin Backhouse discovered Apport read various process-specific files with
 elevated privileges during crash dump generation. This could could be used
 by a local attacker to generate a crash report for a privileged process
 that is readable by an unprivileged user. (CVE-2019-15790)");

  script_tag(name:"affected", value:"'apport' package(s) on Ubuntu 14.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"apport", ver:"2.14.1-0ubuntu3.29+esm2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-apport", ver:"2.14.1-0ubuntu3.29+esm2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-apport", ver:"2.14.1-0ubuntu3.29+esm2", rls:"UBUNTU14.04 LTS"))) {
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
