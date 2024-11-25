# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844696");
  script_cve_id("CVE-2020-25650", "CVE-2020-25651", "CVE-2020-25652", "CVE-2020-25653");
  script_tag(name:"creation_date", value:"2020-11-05 04:00:56 +0000 (Thu, 05 Nov 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-03 19:58:00 +0000 (Thu, 03 Dec 2020)");

  script_name("Ubuntu: Security Advisory (USN-4617-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|20\.10)");

  script_xref(name:"Advisory-ID", value:"USN-4617-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4617-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'spice-vdagent' package(s) announced via the USN-4617-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Matthias Gerstner discovered that SPICE vdagent incorrectly handled the
active_xfers hash table. A local attacker could possibly use this issue to
cause SPICE vdagent to consume memory, resulting in a denial of service.
(CVE-2020-25650)

Matthias Gerstner discovered that SPICE vdagent incorrectly handled the
active_xfers hash table. A local attacker could possibly use this issue to
cause SPICE vdagent to consume memory, resulting in a denial of service, or
obtain sensitive file contents. (CVE-2020-25651)

Matthias Gerstner discovered that SPICE vdagent incorrectly handled a large
number of client connections. A local attacker could possibly use this
issue to cause SPICE vdagent to consume resources, resulting in a denial of
service. (CVE-2020-25652)

Matthias Gerstner discovered that SPICE vdagent incorrectly handled client
connections. A local attacker could possibly use this issue to obtain
sensitive information, paste clipboard contents, and transfer files into
the active session. (CVE-2020-25653)");

  script_tag(name:"affected", value:"'spice-vdagent' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 20.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"spice-vdagent", ver:"0.17.0-1ubuntu2.2", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"spice-vdagent", ver:"0.19.0-2ubuntu0.2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.10") {

  if(!isnull(res = isdpkgvuln(pkg:"spice-vdagent", ver:"0.20.0-1ubuntu0.1", rls:"UBUNTU20.10"))) {
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
